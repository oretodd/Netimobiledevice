using Microsoft.Extensions.Logging;
using Netimobiledevice.Afc;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.InstallationProxy;
using Netimobiledevice.Lockdown;
using Netimobiledevice.NotificationProxy;
using Netimobiledevice.Plist;
using Netimobiledevice.SpringBoardServices;
using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Backup;

/// <summary>
/// Communication with the Backup service to either create or restore a backup as well as configuring the backup encryption password.
/// </summary>
/// <param name="lockdown"></param>
/// <param name="logger"></param>
public sealed class Mobilebackup2Service(
    LockdownServiceProvider lockdown,
    ILogger? logger = null
) : LockdownService(
    lockdown,
    LOCKDOWN_SERVICE_NAME,
    RSD_SERVICE_NAME,
    useEscrowBag: true,
    logger: logger
) {
    private const int MOBILEBACKUP2_VERSION_MAJOR = 400;
    private const int MOBILEBACKUP2_VERSION_MINOR = 0;

    private const string LOCKDOWN_SERVICE_NAME = "com.apple.mobilebackup2";
    private const string RSD_SERVICE_NAME = "com.apple.mobilebackup2.shim.remote";

    private CancellationTokenSource _internalCts = new CancellationTokenSource();
    // #2198 (P1-4): volatile — the flag is SET/CLEARED from the NotificationProxy listener thread and
    // READ from the Backup task's wait loop; without volatile the reader could legally cache a stale
    // value and never observe the clear (or the set).
    private volatile bool _passcodeRequired;

    /// <summary>
    /// #2198 (P1-4): the interval between passcode-wait polls. Constant (was the inline 3000ms literal);
    /// exposed for the wait-loop unit test via the injectable overload of
    /// <see cref="WaitForPasscodeEntryAsync"/>.
    /// </summary>
    private static readonly TimeSpan PasscodePollInterval = TimeSpan.FromSeconds(3);

    /// <summary>
    /// #2198 (P1-4): the library-default passcode-wait deadline in SECONDS (5 minutes). Generous enough
    /// for a user to pick up the device and type the passcode; bounded so a walked-away prompt cannot
    /// park the backup forever.
    /// </summary>
    public const int DefaultPasscodeWaitMaxSec = 300;

    /// <summary>
    /// #2198 (P1-4): the deadline on the passcode wait. The prior wait had NO deadline — a user who
    /// walked away from the device prompt parked the backup forever with no signal. When the prompt
    /// stays unanswered past this deadline a dedicated <see cref="PasscodeWaitTimeoutException"/> is
    /// raised so the host maps it to its EXISTING actionable passcode terminal (never a generic fatal).
    /// The hosting ScribeHold.Service overrides it from configuration (<c>PasscodeWaitMaxSec</c>);
    /// a non-positive value disables the deadline (the legacy unbounded wait).
    /// </summary>
    public TimeSpan PasscodeWaitMax { get; set; } = TimeSpan.FromSeconds(DefaultPasscodeWaitMaxSec);

    /// <summary>
    /// ScribeHold fork: cumulative throughput stats from the last Backup() invocation. Populated
    /// just before the DeviceLinkService is disposed, so the caller can log them from the caller's
    /// own logger after Backup returns. Null if Backup was never called.
    /// </summary>
    public (long RxBytes, TimeSpan RxTime, long WxBytes, TimeSpan WxTime)? LastBackupThroughputStats { get; private set; }

    /// <summary>
    /// ScribeHold fork: optional delegate to classify whether a backup file should be discarded
    /// (bytes drained but not written to disk). Set before calling <see cref="Backup"/> to enable
    /// zero-disk-write optimization. When null, all files are written normally.
    /// </summary>
    public Func<string, bool>? ShouldDiscardFile { get; set; }

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): optional host-supplied transport-presence probe, forwarded to the
    /// <see cref="DeviceLinkService"/> so it is consulted — alongside the passive socket probe — when the
    /// generous <c>Preparing</c> silence bound trips. Lets a healthy multi-minute on-device manifest diff
    /// keep waiting instead of being torn down. Set before calling <see cref="Backup"/>; null (default) →
    /// the DeviceLinkService uses the socket-level probe alone.
    /// </summary>
    public DevicePresenceProbe? PresenceProbe { get; set; }

    /// <summary>
    /// iTunes files to be inserted into the Info.plist file.
    /// </summary>
    private static readonly string[] iTunesFiles = [
        "ApertureAlbumPrefs",
        "IC-Info.sidb",
        "IC-Info.sidv",
        "PhotosFolderAlbums",
        "PhotosFolderName",
        "PhotosFolderPrefs",
        "VoiceMemos.plist",
        "iPhotoAlbumPrefs",
        "iTunesApplicationIDs",
        "iTunesPrefs",
        "iTunesPrefs.plist"
    ];

    /// <summary>
    /// Event raised when a file is about to be transferred from the device.
    /// </summary>
    public event EventHandler<BackupFileEventArgs>? BeforeReceivingFile;
    /// <summary>
    /// Event raised when the backup finishes.
    /// </summary>
    public event EventHandler<BackupResultEventArgs>? Completed;
    /// <summary>
    /// Event raised when there is some error during the backup.
    /// </summary>
    public event EventHandler<ErrorEventArgs>? Error;
    /// <summary>
    /// Event raised when a file is received from the device.
    /// </summary>
    public event EventHandler<BackupFileEventArgs>? FileReceived;
    /// <summary>
    /// Event raised when a part of a file has been received from the device.
    /// </summary>
    public event EventHandler<BackupFileEventArgs>? FileReceiving;
    /// <summary>
    /// Event raised when a file transfer has failed due an internal device error.
    /// </summary>
    public event EventHandler<BackupFileErrorEventArgs>? FileTransferError;
    /// <summary>
    /// Event raised when the device requires a passcode to start the backup
    /// </summary>
    public event EventHandler? PasscodeRequiredForBackup;
    /// <summary>
    /// Event raised for signaling the backup progress.
    /// </summary>
    public event ProgressChangedEventHandler? Progress;
    /// <summary>
    /// Event raised when the backup started.
    /// </summary>
    public event EventHandler<BackupStartedEventArgs>? Started;
    /// <summary>
    /// Event raised for signaling different kinds of the backup status.
    /// </summary>
    public event EventHandler<StatusEventArgs>? Status;

    private static bool BackupExists(string backupDirectory, string identifier) {
        string deviceDirectory = Path.Combine(backupDirectory, identifier);
        bool infoPlistExists = File.Exists(Path.Combine(deviceDirectory, "Info.plist"));
        bool manifestPlistExists = File.Exists(Path.Combine(deviceDirectory, "Manifest.plist"));
        bool statusPlistExists = File.Exists(Path.Combine(deviceDirectory, "Status.plist"));
        return infoPlistExists && manifestPlistExists && statusPlistExists;
    }

    private async Task<ResultCode> ChangeBackupEncryptionPassword(string? oldPassword, string? newPassword, BackupEncryptionFlags flag, CancellationToken cancellationToken) {
        DictionaryNode backupDomain = Lockdown.GetValue("com.apple.mobile.backup", null)?.AsDictionaryNode() ?? [];
        backupDomain.TryGetValue("WillEncrypt", out PropertyNode? willEncryptNode);
        bool willEncryptBackup = willEncryptNode?.AsBooleanNode().Value ?? false;

        switch (flag) {
            case BackupEncryptionFlags.Enable: {
                if (willEncryptBackup) {
                    Logger.LogError("ERROR Backup encryption is already enabled. Aborting.");
                    throw new InvalidOperationException("Can't set backup password as one already exists");
                }
                else if (string.IsNullOrEmpty(newPassword)) {
                    Logger.LogError("No backup password given. Aborting.");
                    throw new ArgumentException("password can't be null or empty");
                }
                break;
            }
            case BackupEncryptionFlags.ChangePassword: {
                if (!willEncryptBackup) {
                    Logger.LogError("Error Backup encryption is not enabled so can't change password. Aborting");
                    throw new InvalidOperationException("Backup encryption isn't enabled so can't change password");
                }
                break;
            }
            case BackupEncryptionFlags.Disable: {
                if (!willEncryptBackup) {
                    Logger.LogError("ERROR Backup encryption is already disabled. Aborting.");
                    throw new InvalidOperationException("Can't remove backup password as none exists");
                }
                else if (string.IsNullOrEmpty(oldPassword)) {
                    Logger.LogError("No backup password given. Aborting.");
                    throw new ArgumentException("password can't be null or empty");
                }
                break;
            }
        }

        if (string.IsNullOrEmpty(newPassword) && string.IsNullOrEmpty(oldPassword)) {
            throw new Mobilebackup2Exception("Both newPassword and oldPassword can't be null or empty");
        }

        using (DeviceLinkService dl = await GetDeviceLink(string.Empty, true, true, cancellationToken).ConfigureAwait(false)) {
            DictionaryNode message = new DictionaryNode() {
                { "MessageName", new StringNode("ChangePassword") },
                { "TargetIdentifier", new StringNode(Lockdown.Udid) },
            };
            if (!string.IsNullOrEmpty(oldPassword)) {
                message.Add("OldPassword", new StringNode(oldPassword));
            }
            if (!string.IsNullOrEmpty(newPassword)) {
                message.Add("NewPassword", new StringNode(newPassword));
            }
            await dl.SendProcessMessage(message, cancellationToken).ConfigureAwait(false);
            return await dl.DlLoop(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates the Info.plist dictionary.
    /// </summary>
    /// <returns>The created Info.plist as a DictionaryNode.</returns>
    private async Task<DictionaryNode> CreateInfoPlist(AfcService afc, CancellationToken cancellationToken) {
        DictionaryNode rootNode = Lockdown.GetValue()?.AsDictionaryNode() ?? [];
        PropertyNode? itunesSettings = Lockdown.GetValue("com.apple.iTunes", null);

        // Get the minimum required iTunes version from the device or use a specified default 
        PropertyNode minItunesVersion = Lockdown.GetValue("com.apple.mobile.iTunes", "MinITunesVersion") ?? new StringNode("10.0.1");

        DictionaryNode appDict = [];
        ArrayNode installedApps = [];
        using (InstallationProxyService installationProxyService = new InstallationProxyService(Lockdown)) {
            using (SpringBoardServicesService springBoardServicesService = new SpringBoardServicesService(Lockdown)) {
                try {
                    ArrayNode apps = await installationProxyService.Browse(
                        new DictionaryNode() { { "ApplicationType", new StringNode("User") } },
                        [
                            new StringNode("CFBundleIdentifier"),
                            new StringNode("ApplicationSINF"),
                            new StringNode("iTunesMetadata")
                        ],
                        cancellationToken).ConfigureAwait(false);
                    foreach (DictionaryNode app in apps.Cast<DictionaryNode>()) {
                        if (app.TryGetValue("CFBundleIdentifier", out PropertyNode? bundleIdNode)) {
                            installedApps.Add(bundleIdNode);

                            string bundleId = bundleIdNode.AsStringNode().Value;
                            if (app.TryGetValue("ApplicationSINF", out PropertyNode? applicationSinfNode) && app.TryGetValue("iTunesMetadata", out PropertyNode? itunesMetadataNode)) {
                                appDict.Add(bundleId, new DictionaryNode() {
                                    { "ApplicationSINF", applicationSinfNode },
                                    { "iTunesMetadata", itunesMetadataNode },
                                    { "PlaceholderIcon", await springBoardServicesService.GetIconPngDataAsync(bundleId, cancellationToken).ConfigureAwait(false) },
                                });
                            }
                        }
                    }
                }
                catch (Exception ex) {
                    Logger.LogWarning(ex, "Failed to create application list for Info.plist");
                }

                DictionaryNode files = [];
                foreach (string iTuneFile in iTunesFiles) {
                    string filePath = $"/iTunes_Control/iTunes/{iTuneFile}";
                    try {
                        byte[] dataBuffer = await afc.GetFileContents(filePath, cancellationToken) ?? [];
                        files.Add(iTuneFile, new DataNode(dataBuffer));
                    }
                    catch (AfcException ex) {
                        if (ex.AfcError == AfcError.ObjectNotFound) {
                            continue;
                        }
                        else {
                            throw;
                        }
                    }
                }

                DictionaryNode info = new DictionaryNode {
                    { "iTunes Version", minItunesVersion },
                    { "iTunes Files", files },
                    { "Unique Identifier", new StringNode(Lockdown.Udid.ToUpperInvariant()) },
                    { "Target Type", new StringNode("Device") },
                    { "Target Identifier", rootNode["UniqueDeviceID"] },
                    { "Serial Number", rootNode["SerialNumber"] },
                    { "Product Version", rootNode["ProductVersion"] },
                    { "Product Type", rootNode["ProductType"] },
                    { "Installed Applications", installedApps },
                    { "GUID", new StringNode(Guid.NewGuid().ToString()) },
                    { "Display Name", rootNode["DeviceName"] },
                    { "Device Name", rootNode["DeviceName"] },
                    { "Build Version", rootNode["BuildVersion"] },
                    { "Applications", appDict },
                    { "Last Backup Date", new DateNode(DateTime.Now) }
                };

                if (rootNode.TryGetValue("IntegratedCircuitCardIdentity", out PropertyNode? iccidNode)) {
                    info.Add("ICCID", iccidNode);
                }
                if (rootNode.TryGetValue("InternationalMobileEquipmentIdentity", out PropertyNode? imeiNode)) {
                    info.Add("IMEI", imeiNode);
                }
                if (rootNode.TryGetValue("MobileEquipmentIdentifier", out PropertyNode? meidNode)) {
                    info.Add("MEID", meidNode);
                }
                if (rootNode.TryGetValue("PhoneNumber", out PropertyNode? phoneNumberNode)) {
                    info.Add("Phone Number", phoneNumberNode);
                }

                try {
                    byte[] dataBuffer = await afc.GetFileContents("/Books/iBooksData2.plist", cancellationToken).ConfigureAwait(false) ?? [];
                    info.Add("iBooks Data 2", new DataNode(dataBuffer));
                }
                catch (AfcException ex) {
                    if (ex.AfcError != AfcError.ObjectNotFound) {
                        throw;
                    }
                }

                if (itunesSettings != null) {
                    info.Add("iTunes Settings", itunesSettings ?? new DictionaryNode());
                }

                return info;
            }
        }
    }

    private void DeviceLink_BeforeReceivingFile(object? sender, BackupFileEventArgs e) {
        BeforeReceivingFile?.Invoke(sender, e);
    }

    private void DeviceLink_Completed(object? sender, BackupResultEventArgs e) {
        Completed?.Invoke(sender, e);
    }

    private void DeviceLink_Error(object? sender, ErrorEventArgs e) {
        Error?.Invoke(sender, e);
    }

    private void DeviceLink_FileReceived(object? sender, BackupFileEventArgs e) {
        FileReceived?.Invoke(sender, e);
    }

    private void DeviceLink_FileReceiving(object? sender, BackupFileEventArgs e) {
        FileReceiving?.Invoke(sender, e);
    }

    private void DeviceLink_FileTransferError(object? sender, BackupFileErrorEventArgs e) {
        FileTransferError?.Invoke(sender, e);
    }

    private void DeviceLink_Progress(object? sender, ProgressChangedEventArgs e) {
        Progress?.Invoke(sender, e);
    }

    private void DeviceLink_Status(object? sender, StatusEventArgs e) {
        Status?.Invoke(sender, e);
    }
    private void DeviceLink_Started(object? sender, BackupStartedEventArgs e) {
        Started?.Invoke(sender, e);
    }

    private async Task<DeviceLinkService> GetDeviceLink(string backupDirectory, bool ignoreTransferErrors, bool performBackupSizeCheck, CancellationToken cancellationToken) {
        DeviceLinkService dl = new DeviceLinkService(this.Service, backupDirectory, this.Lockdown.OsVersion, ignoreTransferErrors, performBackupSizeCheck, Logger);
        dl.ShouldDiscardFile = this.ShouldDiscardFile;
        // #2197 (P0-B): forward the presence probe BEFORE the version exchange so it is armed for both the
        // version-exchange reads and the subsequent Preparing-phase wait.
        dl.PresenceProbe = this.PresenceProbe;
        await dl.VersionExchange(MOBILEBACKUP2_VERSION_MAJOR, MOBILEBACKUP2_VERSION_MINOR, cancellationToken).ConfigureAwait(false);
        await VersionExchange(dl, cancellationToken).ConfigureAwait(false);
        return dl;
    }

    /// <summary>
    /// Exchange versions with the device and assert that the device supports our version of the protocol.
    /// </summary>
    /// <param name="dl">Initialized device link.</param>
    private static async Task VersionExchange(DeviceLinkService dl, CancellationToken cancellationToken) {
        ArrayNode supportedVersions = [
            new RealNode(2.0),
            new RealNode(2.1)
        ];
        await dl.SendProcessMessage(
            new DictionaryNode() {
                {"MessageName", new StringNode("Hello") },
                {"SupportedProtocolVersions", supportedVersions }
            },
            cancellationToken
        ).ConfigureAwait(false);

        // #2197 (P0-D): the mb2 Hello response is the third pre-DlLoop version-exchange read — bound it
        // like the other two so a busy-but-silent backupd on a resumed session feeds reconnect in seconds
        // instead of waiting the coarse ~10-minute stream read and then dead-ending as fatal.
        ArrayNode reply = await dl.ReceiveVersionExchangeMessage(cancellationToken).ConfigureAwait(false);
        if (reply[0].AsStringNode().Value != "DLMessageProcessMessage" || reply[1].AsDictionaryNode()["ErrorCode"].AsIntegerNode().Value != 0) {
            throw new Mobilebackup2Exception("Found error in response during version exchange");
        }
        if (!supportedVersions.Contains(reply[1].AsDictionaryNode()["ProtocolVersion"])) {
            throw new Mobilebackup2Exception("Unsuppored protocol version found");
        }
    }

    /// <summary>
    /// Backup a device
    /// </summary>
    /// <param name="fullBackup">Whether to do a full backup; if true any previous backup attempts will be discarded</param>
    /// <param name="ignoreTransferErrors">Whether to skip over any transfer errors</param>
    /// <param name="performBackupSizeCheck">Whether to check that the size of the backup will fit onto this device</param>
    /// <param name="backupDirectory">Directory to write backup to</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public async Task<ResultCode> Backup(
        bool fullBackup = true,
        bool ignoreTransferErrors = true,
        bool performBackupSizeCheck = true,
        string backupDirectory = ".",
        CancellationToken cancellationToken = default
    ) {
        _internalCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        string deviceDirectory = Path.Combine(backupDirectory, Lockdown.Udid);
        Directory.CreateDirectory(deviceDirectory);

        // #2197 (P0-C): true once we observe a drop-class exception the host coordinator will RESUME
        // (an inter-message timeout, the new version-exchange timeout, or a transient IOException). On a
        // quiet abandon we must NOT send CancelBackup (a non-standard, fork-invented mb2 message that
        // tells the device to cancel the very session we are about to resume) and must NOT send
        // DLMessageDisconnect — we just tear the socket down (DeviceLinkService.Dispose closes it), so the
        // resumed session finds backupd still holding the in-progress snapshot.
        bool quietAbandon = false;
        // #2197 (P0-D): GetDeviceLink is now INSIDE the try so a version-exchange failure still runs the
        // finally (app-layer teardown + throughput capture + dispose), rather than escaping it.
        DeviceLinkService? dl = null;
        try {
            dl = await GetDeviceLink(backupDirectory, ignoreTransferErrors, performBackupSizeCheck, _internalCts.Token).ConfigureAwait(false);
            dl.BeforeReceivingFile += DeviceLink_BeforeReceivingFile;
            dl.Completed += DeviceLink_Completed;
            dl.FileReceived += DeviceLink_FileReceived;
            dl.FileReceiving += DeviceLink_FileReceiving;
            dl.FileTransferError += DeviceLink_FileTransferError;
            dl.Progress += DeviceLink_Progress;
            dl.Status += DeviceLink_Status;
            dl.Started += DeviceLink_Started;

            using (NotificationProxyService np = new NotificationProxyService(this.Lockdown)) {
                np.ReceivedNotification += NotificationProxy_ReceivedNotification;
                await np.ObserveNotificationAsync(ReceivableNotification.SyncCancelRequest).ConfigureAwait(false);
                await np.ObserveNotificationAsync(ReceivableNotification.LocalAuthenticationUiPresented).ConfigureAwait(false);
                await np.ObserveNotificationAsync(ReceivableNotification.LocalAuthenticationUiDismissed).ConfigureAwait(false);
                np.Start();

                using (AfcService afc = new AfcService(this.Lockdown)) {
                    using (BackupLock backupLock = new BackupLock(afc, np)) {
                        await backupLock.AquireBackupLock(_internalCts.Token).ConfigureAwait(false);

                        // Create Info.plist
                        string infoPlistPath = Path.Combine(deviceDirectory, "Info.plist");
                        DictionaryNode infoPlist = await CreateInfoPlist(afc, _internalCts.Token).ConfigureAwait(false);
                        using (FileStream fs = File.OpenWrite(infoPlistPath)) {
                            byte[] infoPlistData = PropertyList.SaveAsByteArray(infoPlist, PlistFormat.Xml);
                            await fs.WriteAsync(infoPlistData, _internalCts.Token).ConfigureAwait(false);
                            FileReceived?.Invoke(this, new BackupFileEventArgs(new BackupFile(string.Empty, infoPlistPath, deviceDirectory)));
                        }

                        // Create Manifest.plist if doesn't exist.
                        string manifestPlistPath = Path.Combine(deviceDirectory, "Manifest.plist");
                        if (fullBackup && File.Exists(manifestPlistPath)) {
                            File.Delete(manifestPlistPath);
                        }
                        else if (!fullBackup && !File.Exists(manifestPlistPath)) {
                            // #2197 (P0-E): make the silent incremental→full degradation LOUD. When
                            // Manifest.plist is missing an incremental backup silently becomes a FULL
                            // backup — a full re-transfer of the whole device. The behavior is UNCHANGED
                            // here (never alter it); this WARN just makes the degradation diagnosable in a
                            // single run instead of being invisible.
                            Logger.LogWarning(
                                "Requested incremental backup but Manifest.plist is missing at {ManifestPath} — degrading to a FULL backup (whole-device re-transfer) (#2197 P0-E)",
                                manifestPlistPath);
                            fullBackup = true;
                        }

                        // Create Status.plist file if doesn't exist.
                        // #2198 (P1-3): written ATOMICALLY (temp + move-overwrite) so an interrupted
                        // write can never leave a torn Status.plist that poisons the next incremental
                        // attempt; and an EXISTING torn/unparseable Status.plist is repaired to a clean
                        // incremental baseline at attempt start (never silently degrading to FULL).
                        string statusPlistPath = Path.Combine(deviceDirectory, "Status.plist");
                        if (fullBackup || !File.Exists(statusPlistPath)) {
                            BackupStatus status = new BackupStatus() { IsFullBackup = fullBackup };
                            await AtomicFile.WriteAllBytesAsync(statusPlistPath, PropertyList.SaveAsByteArray(status.ToPlist(), PlistFormat.Binary), _internalCts.Token).ConfigureAwait(false);
                        }
                        else if (!IsStatusPlistReadable(statusPlistPath)) {
                            Logger.LogWarning(
                                "Status.plist at {StatusPath} is torn/unparseable — rewriting a clean incremental baseline (New/Finished); the backup stays INCREMENTAL, never degrading to full (#2198 P1-3)",
                                statusPlistPath);
                            BackupStatus repaired = new BackupStatus() { IsFullBackup = false };
                            await AtomicFile.WriteAllBytesAsync(statusPlistPath, PropertyList.SaveAsByteArray(repaired.ToPlist(), PlistFormat.Binary), _internalCts.Token).ConfigureAwait(false);
                        }

                        DictionaryNode message = new DictionaryNode() {
                                { "MessageName", new StringNode("Backup") },
                                { "TargetIdentifier", new StringNode(Lockdown.Udid) }
                            };
                        await dl.SendProcessMessage(message, cancellationToken).ConfigureAwait(false);

                        // Wait for 3 seconds to see if the device passcode is requested and then keep
                        // waiting till the passcode has been entered — but never past the PasscodeWaitMax
                        // deadline (#2198 P1-4): an unanswered prompt surfaces a dedicated
                        // PasscodeWaitTimeoutException (an actionable terminal, never a generic fatal).
                        await WaitForPasscodeEntryAsync(
                            () => _passcodeRequired, PasscodePollInterval, PasscodeWaitMax, Logger,
                            _internalCts.Token).ConfigureAwait(false);

                        return await dl.DlLoop(_internalCts.Token).ConfigureAwait(false);
                    }
                }
            }
        }
        catch (Exception ex) when (IsResumeDropClass(ex)) {
            // #2197 (P0-C): a drop-class the host will RESUME. Flag it so the finally SKIPS the
            // CancelBackup + Disconnect that would tell the busy device to cancel the very session we are
            // about to resume, and just tears the socket down. Rethrow so the coordinator classifies it.
            quietAbandon = true;
            throw;
        }
        finally {
            // #2197 (P0-C): the app-layer teardown. On a normal/terminal unwind we send CancelBackup then
            // let Dispose close the socket. On a QUIET ABANDON (a drop-class the host will resume) we skip
            // BOTH CancelBackup (a non-standard fork-invented mb2 message that cancels the very session we
            // are about to resume) and DLMessageDisconnect — we just tear the socket down. Either way the
            // outcome is LOGGED (previously swallowed), so a live run explains what teardown happened.
            if (dl != null) {
                if (quietAbandon) {
                    Logger.LogInformation(
                        "Backup teardown: quiet abandon (drop-class the host will resume) — CancelBackup + Disconnect SKIPPED, tearing the socket down only (#2197 P0-C)");
                }
                else {
                    // ScribeHold fork: send CancelBackup to cleanly terminate the backup session on the
                    // device side. On successful completion the device has already closed its end of the
                    // connection, so the write may throw SocketError 10053 (WSAECONNABORTED) or hang
                    // indefinitely on a half-closed SSL socket. Use a 5-second timeout to prevent hanging
                    // forever, and scope the catches so we don't swallow unexpected exceptions.
                    try {
                        using var cancelBackupCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        cancelBackupCts.CancelAfter(TimeSpan.FromSeconds(5));
                        DictionaryNode message = new DictionaryNode() {
                            { "MessageName", new StringNode("CancelBackup") },
                            { "TargetIdentifier", new StringNode(Lockdown.Udid) }
                        };
                        await dl.SendProcessMessage(message, cancelBackupCts.Token).ConfigureAwait(false);
                        Logger.LogInformation("Backup teardown: CancelBackup sent (#2197 P0-E)");
                    }
                    catch (IOException ex) {
                        Logger.LogInformation("Backup teardown: CancelBackup send failed (expected on a closed peer): {Message} (#2197 P0-E)", ex.Message);
                    }
                    catch (OperationCanceledException) {
                        Logger.LogInformation("Backup teardown: CancelBackup send timed out after 5s (#2197 P0-E)");
                    }
                }

                // ScribeHold fork: capture throughput stats before dl is disposed. Exposed to the
                // caller via LastBackupThroughputStats so they can log under their own category.
                // Runs regardless of CancelBackup outcome so stats are never lost.
                LastBackupThroughputStats = dl.GetAndResetThroughputStats();

                try {
                    // #2197 (P0-C): Dispose closes the socket. On a quiet abandon it must NOT send the
                    // DLMessageDisconnect — DeviceLinkService.Dispose honors DisposeQuietly for that.
                    if (quietAbandon) {
                        dl.DisposeQuietly();
                    }
                    else {
                        dl.Dispose();
                    }
                }
                catch {
                    // Do nothing for these exceptions
                }
            }
        }
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-C): true when <paramref name="ex"/> is a drop-class the host coordinator
    /// will RESUME rather than treat as terminal — a between-message inter-message timeout, the new
    /// version-exchange timeout, or a transient transport <see cref="IOException"/>. On these we quiet-abandon
    /// (skip CancelBackup + Disconnect) so the resumed session finds backupd still holding the in-progress
    /// snapshot. A user/terminal cancellation is NOT a drop-class (the normal CancelBackup path runs).
    /// </summary>
    private static bool IsResumeDropClass(Exception ex) {
        return ex is DeviceLinkInterMessageTimeoutException
            or DeviceLinkVersionExchangeTimeoutException
            // #2198 (P1-1): a bounded per-chunk send timeout is the write-side twin of the inter-message
            // read timeout — same drop-class, same quiet abandon, same reconnect-and-resume.
            or ServiceConnectionSendTimeoutException
            or IOException;
    }

    /// <summary>
    /// #2198 (P1-4): the bounded passcode wait, static with the flag/clock injected so the deadline
    /// behavior is unit-testable without a live device. Polls <paramref name="passcodeRequired"/> every
    /// <paramref name="pollInterval"/>; returns normally once the passcode prompt clears (or was never
    /// shown). When the prompt stays raised past <paramref name="maxWait"/>, throws a dedicated
    /// <see cref="PasscodeWaitTimeoutException"/> — an actionable user-action terminal, never a generic
    /// fatal or a transient drop. A non-positive <paramref name="maxWait"/> disables the deadline
    /// (legacy unbounded wait). A caller cancellation always propagates as-is.
    /// </summary>
    internal static async Task WaitForPasscodeEntryAsync(
        Func<bool> passcodeRequired,
        TimeSpan pollInterval,
        TimeSpan maxWait,
        ILogger logger,
        CancellationToken cancellationToken) {
        long waitStartTicks = System.Diagnostics.Stopwatch.GetTimestamp();
        do {
            await Task.Delay(pollInterval, cancellationToken).ConfigureAwait(false);
            if (passcodeRequired() && IsPasscodeWaitExpired(System.Diagnostics.Stopwatch.GetElapsedTime(waitStartTicks), maxWait)) {
                logger.LogError(
                    "Device passcode prompt unanswered past the {MaxSec:0.###}s deadline — surfacing the actionable passcode terminal (#2198 P1-4)",
                    maxWait.TotalSeconds);
                throw new PasscodeWaitTimeoutException(maxWait);
            }
        } while (passcodeRequired());
    }

    /// <summary>
    /// #2198 (P1-4): the pure deadline decision — expired only when a positive deadline is configured
    /// and the elapsed wait has reached it. A non-positive deadline disables the bound (never expires),
    /// preserving the legacy unbounded wait for a host that opts out. Pure + internal for the fork test.
    /// </summary>
    internal static bool IsPasscodeWaitExpired(TimeSpan waited, TimeSpan maxWait) {
        return maxWait > TimeSpan.Zero && waited >= maxWait;
    }

    /// <summary>
    /// #2198 (P1-3): true when the Status.plist at <paramref name="statusPlistPath"/> parses as a
    /// well-formed status plist. A torn/truncated file (interrupted write) returns false so the caller
    /// repairs it to a clean incremental baseline instead of handing the device a malformed plist.
    /// </summary>
    private bool IsStatusPlistReadable(string statusPlistPath) {
        try {
            DictionaryNode node = PropertyList.LoadFromByteArray(File.ReadAllBytes(statusPlistPath)).AsDictionaryNode();
            BackupStatus.ParsePlist(node, Logger);
            return true;
        }
        catch (Exception ex) {
            Logger.LogDebug(ex, "Status.plist at {StatusPath} failed to parse (#2198 P1-3)", statusPlistPath);
            return false;
        }
    }

    private void NotificationProxy_ReceivedNotification(object? sender, ReceivedNotificationEventArgs e) {
        if (e.Event == ReceivableNotification.LocalAuthenticationUiPresented) {
            // iOS versions 15.7.1 and anything 16.1 or newer will require you to input a passcode before
            // it can start a backup so we make sure to notify the user about this.
            if ((Lockdown.OsVersion >= new Version(15, 7, 1) && Lockdown.OsVersion < new Version(16, 0)) ||
                Lockdown.OsVersion >= new Version(16, 1)) {
                _passcodeRequired = true;
                PasscodeRequiredForBackup?.Invoke(this, EventArgs.Empty);
            }
        }
        else if (e.Event == ReceivableNotification.LocalAuthenticationUiDismissed) {
            _passcodeRequired = false;
        }
        else if (e.Event == ReceivableNotification.SyncCancelRequest) {
            _internalCts.Cancel();
        }
    }

    /// <summary>
    /// Restore a pre existing backup to the connected device.
    /// </summary>
    /// <param name="backupDirectory">Path to the backup directory being restored</param>
    /// <param name="system">Whether to restore system files; defaults to false</param>
    /// <param name="reboot">Reboots the device when done; defaults to false</param>
    /// <param name="copy">Create a copy of the backup folder before restoring; defaults to true</param>
    /// <param name="settings">Restore device settings; defaults to true</param>
    /// <param name="remove">Remove items which aren't being restored; defaults to false</param>
    /// <param name="password">The password for the backup if it is encrypted</param>
    /// <param name="source">Identifier of device to restore it's backup</param>
    public async Task<ResultCode> Restore(string backupDirectory, bool system = false, bool reboot = false,
        bool copy = true,
        bool settings = true, bool remove = false, string password = "", string source = "",
        bool ignoreTransferErrors = false, CancellationToken cancellationToken = default) {
        if (string.IsNullOrEmpty(source)) {
            source = Lockdown.Udid;
        }

        if (!BackupExists(backupDirectory, source)) {
            throw new Mobilebackup2Exception("Backup not found");
        }

        using (DeviceLinkService dl =
               await GetDeviceLink(backupDirectory, ignoreTransferErrors, true, cancellationToken)
                   .ConfigureAwait(false)) {
            dl.BeforeReceivingFile += DeviceLink_BeforeReceivingFile;
            dl.Completed += DeviceLink_Completed;
            dl.FileReceived += DeviceLink_FileReceived;
            dl.FileReceiving += DeviceLink_FileReceiving;
            dl.FileTransferError += DeviceLink_FileTransferError;
            dl.Progress += DeviceLink_Progress;
            dl.Status += DeviceLink_Status;
            dl.Started += DeviceLink_Started;

            using (NotificationProxyService np = new NotificationProxyService(this.Lockdown)) {
                using (AfcService afc = new AfcService(this.Lockdown)) {
                    using (BackupLock backupLock = new BackupLock(afc, np)) {
                        await backupLock.AquireBackupLock(cancellationToken).ConfigureAwait(false);

                        string manifestPlistPath = Path.Combine(backupDirectory, source, "Manifest.plist");
                        DictionaryNode manifestPlist;
                        using (FileStream fs = new FileStream(manifestPlistPath, FileMode.Open, FileAccess.Read)) {
                            PropertyNode plist = await PropertyList.LoadAsync(fs).ConfigureAwait(false);
                            manifestPlist = plist.AsDictionaryNode();
                        }

                        bool isEncrypted = false;
                        if (manifestPlist.TryGetValue("IsEncrypted", out PropertyNode? isEncryptedNode)) {
                            isEncrypted = isEncryptedNode.AsBooleanNode().Value;
                        }

                        DictionaryNode options = new DictionaryNode() {
                            { "RestoreShouldReboot", new BooleanNode(reboot) },
                            { "RestoreDontCopyBackup", new BooleanNode(!copy) },
                            { "RestorePreserveSettings", new BooleanNode(settings) },
                            { "RestoreSystemFiles", new BooleanNode(system) },
                            { "RemoveItemsNotRestored", new BooleanNode(remove) }
                        };

                        if (isEncrypted) {
                            if (string.IsNullOrEmpty(password)) {
                                options.Add("Password", new StringNode(password));
                            }
                            else {
                                Logger.LogError("Backup is encrypted, but no password is supplied");
                                throw new Mobilebackup2Exception("Password missing from encrypted backup restore");
                            }
                        }

                        DictionaryNode message = new DictionaryNode() {
                            { "MessageName", new StringNode("Restore") },
                            { "TargetIdentifier", new StringNode(Lockdown.Udid) },
                            { "SourceIdentifier", new StringNode(source) },
                            { "Options", options },
                        };
                        await dl.SendProcessMessage(message, cancellationToken).ConfigureAwait(false);

                        return await dl.DlLoop(cancellationToken).ConfigureAwait(false);
                    }
                }
            }
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="currentPassword"></param>
    /// <param name="newPassword"></param>
    public async Task<ResultCode> ChangeBackupPassword(string currentPassword, string newPassword,
        CancellationToken cancellationToken = default) {
        return await ChangeBackupEncryptionPassword(currentPassword, newPassword,
            BackupEncryptionFlags.ChangePassword, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Enables encrypted backups by setting a password for backups to use provided
    /// the phone currently has encrypted backups disabled. 
    /// </summary>
    /// <param name="password">The password to set for backup encryption</param>
    public async Task<ResultCode> SetBackupPassword(string password, CancellationToken cancellationToken = default) {
        return await ChangeBackupEncryptionPassword(null, password, BackupEncryptionFlags.Enable, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Disables encrypted backups on the device by removing the password for backups
    /// </summary>
    /// <param name="currentPassword">The current password for the enabled backup encryption</param>
    public async Task<ResultCode> RemoveBackupPassword(string currentPassword,
        CancellationToken cancellationToken = default) {
        return await ChangeBackupEncryptionPassword(currentPassword, null, BackupEncryptionFlags.Disable,
            cancellationToken).ConfigureAwait(false);
    }
}
