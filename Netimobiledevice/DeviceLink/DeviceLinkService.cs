using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.EndianBitConversion;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.DeviceLink;

public delegate void SendFileErrorEventHandler(DictionaryNode errorNode, string fileName);

/// <summary>
/// ScribeHold fork (#2181): raised when the DlLoop inter-message silence bound trips — the device
/// went silent BETWEEN mb2 messages for longer than the (transport-aware, USB-tight) bound. This is a
/// BOUNDED, CLASSIFIABLE transport-drop signal that FEEDS reconnect-and-resume, NOT a terminal
/// failure. It derives from <see cref="TimeoutException"/> so any existing generic timeout handling
/// still catches it, while the dedicated type lets the coordinator classify it as a transient drop
/// (the same class as a USB socket bump) rather than a genuine device failure. It is raised only for
/// USB (WiFi keeps its loose behavior); it fires in SECONDS instead of waiting the ~10-minute
/// <c>SERVICE_READ_TIMEOUT_MS</c> stream read.
/// </summary>
public sealed class DeviceLinkInterMessageTimeoutException : TimeoutException
{
    public DeviceLinkInterMessageTimeoutException(TimeSpan bound)
        : base($"Device went silent between DeviceLink messages for longer than the inter-message bound ({bound.TotalSeconds:0.###}s)")
    {
        Bound = bound;
    }

    /// <summary>The inter-message silence bound that was exceeded.</summary>
    public TimeSpan Bound { get; }
}

/// <summary>
/// ScribeHold fork (#2197, P0-D): raised when one of the pre-DlLoop version-exchange reads — the
/// DLMessageVersionExchange read, the DLMessageDeviceReady read, or the mb2 <c>Hello</c> response read —
/// stays silent longer than the (transport-aware, USB-tight) version-exchange bound. Before this bound
/// existed, a RESUMED session's version exchange went straight to the coarse ~10-minute stream read: a
/// busy <c>backupd</c> still unwinding a cancelled diff left the resume waiting the full 10 minutes and
/// then dead-ending as a bare <see cref="TimeoutException"/> → generic catch → fatal on attempt 1/3.
///
/// It derives from <see cref="TimeoutException"/> — exactly like
/// <see cref="DeviceLinkInterMessageTimeoutException"/> — so the host's inner <c>catch (TimeoutException)</c>
/// ladder still captures it, while the dedicated type lets the coordinator classify it as a recoverable
/// transport drop (reconnect-and-resume with escalating backoff sized for backupd's release) rather than
/// a terminal failure. Raised only for USB; WiFi keeps its loose behavior and never applies the bound.
/// </summary>
public sealed class DeviceLinkVersionExchangeTimeoutException : TimeoutException
{
    public DeviceLinkVersionExchangeTimeoutException(TimeSpan bound)
        : base($"Device went silent during the DeviceLink version exchange for longer than the version-exchange bound ({bound.TotalSeconds:0.###}s)")
    {
        Bound = bound;
    }

    /// <summary>The version-exchange bound that was exceeded.</summary>
    public TimeSpan Bound { get; }
}

/// <summary>
/// ScribeHold fork (#2197, P0-B): an optional host-supplied presence probe. Given the loop's
/// cancellation token, returns <c>true</c> when the device is still present (e.g. via usbmux presence),
/// <c>false</c> when it is known gone. The DlLoop consults it — in addition to the passive socket probe —
/// when the generous <c>Preparing</c> silence bound trips, so a healthy multi-minute on-device diff keeps
/// waiting rather than being torn down. Optional and default-null: when null the DlLoop uses the
/// socket-level probe alone (the host wires usbmux presence in a follow-up wave).
/// </summary>
/// <param name="cancellationToken">The loop's cancellation token.</param>
/// <returns>A task yielding <c>true</c> if the device is still present, <c>false</c> if known gone.</returns>
public delegate Task<bool> DevicePresenceProbe(CancellationToken cancellationToken);

internal sealed class DeviceLinkService : IDisposable {
    private const int BULK_OPERATION_ERROR = -13;
    private const uint FILE_TRANSFER_TERMINATOR = 0x00;
    // ScribeHold fork: bumped 5 → 10 minutes. iOS's "build incremental diff" prep window on
    // large devices (iPhone 16 Pro Max heavy users, iOS 26.x) regularly takes 5–6 minutes
    // between passcode-accepted and the first PROGRESS-TICK. The original 5-minute value was
    // on the wrong side of that variance and produced spurious TimeoutException failures.
    private const int SERVICE_READ_TIMEOUT_MS = 10 * 60 * 1000;
    // ScribeHold fork (#2081): once the device has reported SnapshotState=Finished (the terminal
    // backup state), the DlLoop switches its next ReceiveMessage from the long SERVICE_READ_TIMEOUT_MS
    // block to this short bound. On a healthy session the device immediately sends the terminating
    // DLMessageProcessMessage and this read returns it well inside 5 s; on the desync this fix targets
    // (device Finished but holds the TCP connection OPEN — no FIN, no final message — observed live on
    // WiFi, #2081) the read instead times out quickly and the loop completes gracefully as success
    // rather than blocking ~10 min and then failing. Kept short so a stuck-but-finished session is
    // released promptly without risking a premature exit on a still-arriving final message.
    private const int FINISHED_FINAL_READ_TIMEOUT_MS = 5 * 1000;

    // ScribeHold fork (#2181): the USB-tight inter-message silence bound the DlLoop applies BETWEEN
    // messages. A gap longer than this — the device going silent between mb2 messages — is a wedge
    // signal that trips in SECONDS and FEEDS reconnect-and-resume, instead of relying on the coarse
    // ~10-minute SERVICE_READ_TIMEOUT_MS stream read. This is the library-carried USB-tight fallback
    // (matches BackupConfiguration.UsbInterMessageSilenceBoundSec = 30 default, Task 3); the host may
    // override it via SetUsbInterMessageSilenceBound so the real threshold originates in config.
    // WiFi keeps its loose behavior (the bound is applied only when the transport is USB).
    private static readonly TimeSpan DefaultUsbInterMessageSilenceBound = TimeSpan.FromSeconds(30);

    // ScribeHold fork (#2193): the generous PRE-first-file Preparing-phase silence bound. During
    // Backup_Preparing the device legitimately goes silent for MINUTES while it builds its on-device
    // manifest diff — the tight inter-message bound above must NOT interrupt that healthy diff. Until
    // the first real FileReceiving event fires (real backup-file content flowing), DlLoop applies THIS
    // generous bound; after it, the tight in-transfer bound governs. Library default matches the host
    // BackupConfiguration.UsbPreparingStallThresholdSec default (4 min); the host overrides it via the
    // connection's TransportTimeoutPolicy.PreparingSilenceBound.
    private static readonly TimeSpan DefaultUsbPreparingSilenceBound = TimeSpan.FromMinutes(4);

    // ScribeHold fork (#2197, P0-D): the per-read version-exchange bound the pre-DlLoop reads apply on
    // USB. A resumed session's version exchange that goes silent longer than this — a busy backupd still
    // unwinding a cancelled diff — trips a bounded DeviceLinkVersionExchangeTimeoutException in seconds
    // and feeds reconnect-and-resume, instead of waiting the coarse ~10-minute stream read and then
    // dead-ending as fatal. Library default matches the host BackupConfiguration.UsbVersionExchangeBoundSec
    // (35s); the host overrides it via the connection's TransportTimeoutPolicy.VersionExchangeBound.
    private static readonly TimeSpan DefaultUsbVersionExchangeBound = TimeSpan.FromSeconds(35);

    // ScribeHold fork (#2197, P0-B): the hard cap on TOTAL continuous Preparing-phase silence. When the
    // generous Preparing bound trips the DlLoop probes the transport and, if healthy, keeps waiting; this
    // caps that probe-and-wait so a genuinely wedged Preparing window can never hang forever even when
    // the socket probe keeps reporting healthy. Library default matches the host default (20 min).
    private static readonly TimeSpan DefaultUsbPreparingHardCap = TimeSpan.FromMinutes(20);

    private readonly ServiceConnection _service;
    private readonly string _rootPath;
    private readonly ILogger _logger;
    private readonly Version _iosVersion;
    private readonly bool _ignoreTransferErrors;
    private readonly bool _performBackupSizeCheck;
    private FileStream? _fileStream;
    private bool _discarding;
    private CancellationTokenSource _internalCancellationTokenSource;

    // ScribeHold fork (#2081): set true once the device reports SnapshotState=Finished — the terminal
    // backup state. Consulted by DlLoop to switch its next ReceiveMessage from the long
    // SERVICE_READ_TIMEOUT_MS block to a short FINISHED_FINAL_READ_TIMEOUT_MS bound, so a device that
    // finishes but holds the connection open (no FIN, no terminating DLMessageProcessMessage — observed
    // live on WiFi, #2081) completes gracefully as success instead of hanging at 100% for ~10 min and
    // then failing. Only ever transitions false→true (a backup never un-finishes), so the early-exit
    // can engage ONLY after the terminal state was genuinely observed — a still-transferring backup is
    // structurally unaffected.
    private bool _finishedObserved;

    // ScribeHold fork: throughput instrumentation — accumulates time spent in the USB/network
    // receive call vs. the disk write call during UploadFiles. Used to diagnose whether backup
    // speed is transfer-bound or disk-bound. Read/reset via GetAndResetThroughputStats().
    private long _rxBytes;
    private long _rxTicks;
    private long _wxBytes;
    private long _wxTicks;

    // ScribeHold fork (#2181): the response-guarantee owner. Hands each handled message a fresh
    // IDeviceLinkResponseGuarantee bound to SendStatusReport, so exactly-one-terminating-response
    // (even under mid-handler cancellation) lives in one testable place instead of scattered
    // if (!IsCancellationRequested) { send } guards.
    private readonly DeviceLinkResponseGuarantees _responseGuarantees;

    // ScribeHold fork (#2181/#2190): the active USB inter-message silence bound the DlLoop applies.
    // Seeded in the ctor from the connection's TransportTimeoutPolicy so the value the host derived
    // from BackupConfiguration.UsbInterMessageSilenceBoundSec (assigned onto the ServiceConnection by
    // LockdownClient, #2190) flows down through the SAME single policy that carries the SSL-handshake
    // watchdog — no separate host call. SetUsbInterMessageSilenceBound remains an explicit override.
    private TimeSpan _usbInterMessageSilenceBound = DefaultUsbInterMessageSilenceBound;

    // ScribeHold fork (#2193): the active generous Preparing-phase silence bound, seeded in the ctor
    // from the connection's TransportTimeoutPolicy (host key UsbPreparingStallThresholdSec) so a normal
    // multi-minute manifest diff is never interrupted. Falls back to DefaultUsbPreparingSilenceBound.
    private TimeSpan _usbPreparingSilenceBound = DefaultUsbPreparingSilenceBound;

    // ScribeHold fork (#2193): latched true on the FIRST real FileReceiving event — the moment the
    // device begins pushing real backup-file content (mb2 UploadFiles). Preparing-phase messages are
    // DownloadFiles/ContentsOfDirectory and never raise FileReceiving, so this flips false→true exactly
    // at the Preparing→in-transfer boundary. DlLoop reads it to select the generous Preparing bound (pre)
    // vs the tight inter-message bound (post). Mirrors the host's RealTransferStarted signal (first
    // FileReceiving), so both ends agree on where Preparing ends. Latch-once: a backup never un-starts.
    private bool _realTransferStarted;

    // ScribeHold fork (#2197, P0-D): the active per-read version-exchange bound, seeded in the ctor from
    // the connection's TransportTimeoutPolicy (host key UsbVersionExchangeBoundSec). Falls back to the
    // library default so a standalone consumer is safe.
    private TimeSpan _usbVersionExchangeBound = DefaultUsbVersionExchangeBound;

    // ScribeHold fork (#2197, P0-B): the active Preparing hard cap, seeded in the ctor from the same
    // policy (host key UsbPreparingHardCapSec). Falls back to the library default.
    private TimeSpan _usbPreparingHardCap = DefaultUsbPreparingHardCap;

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): optional host-supplied presence probe consulted — alongside the
    /// passive socket-level probe — when the generous Preparing silence bound trips, so a healthy
    /// multi-minute on-device manifest diff keeps waiting instead of being torn down. Null (default) →
    /// the DlLoop uses the socket probe alone. The host wires usbmux presence here in a follow-up wave.
    /// </summary>
    public DevicePresenceProbe? PresenceProbe { get; set; }

    /// <summary>
    /// ScribeHold fork: optional delegate to classify whether a file should be discarded (bytes
    /// drained but not written to disk). When null, all files are written normally. When set,
    /// called once per file at the start of the first chunk using the device-side path.
    /// Returns true = discard.
    /// </summary>
    public Func<string, bool>? ShouldDiscardFile { get; set; }

    private Dictionary<string, Func<ArrayNode, CancellationToken, Task>> DeviceLinkHandlers { get; }
    /// <summary>
    /// A list of the files whose transfer failed due to a device error.
    /// </summary>
    private List<BackupFile> FailedFiles { get; } = [];

    public long BytesRead { get; private set; }

    /// <summary>
    /// Event raised when a file is about to be transferred from the device.
    /// </summary>
    public event EventHandler<BackupFileEventArgs>? BeforeReceivingFile;
    /// <summary>
    /// Event raised when the backup finishes.
    /// </summary>
    public event EventHandler<BackupResultEventArgs>? Completed;
    /// <summary>
    /// Event raised when there is a non-fatal error during the backup
    /// </summary>
    public event EventHandler<DetailedErrorEventArgs>? Warning;
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
    /// <summary>
    /// Event raised when a file send to the device has failed due to errors on the application side
    /// </summary>
    public event SendFileErrorEventHandler? SendFileError;

    public DeviceLinkService(ServiceConnection service, string backupDirectory, Version iosVersion, bool ignoreTransferErrors = true, bool performBackupSizeCheck = true, ILogger? logger = null) {
        _service = service;
        _rootPath = backupDirectory;
        _iosVersion = iosVersion;
        _ignoreTransferErrors = ignoreTransferErrors;
        _performBackupSizeCheck = performBackupSizeCheck;
        _logger = logger ?? NullLogger.Instance;

        // #2190: seed the DlLoop inter-message silence bound from the connection's transport policy so
        // the host-configured UsbInterMessageSilenceBoundSec (carried on the ServiceConnection via
        // LockdownClient.TimeoutPolicy) takes effect. Falls back to the USB-tight policy default when
        // the host has not overridden the policy. Only applied when the transport is USB (IsUsbTransport).
        _usbInterMessageSilenceBound = service.TimeoutPolicy.InterMessageSilenceBound;

        // #2193: seed the generous Preparing-phase bound from the SAME transport policy so the host key
        // UsbPreparingStallThresholdSec (carried on the ServiceConnection via LockdownClient.TimeoutPolicy)
        // takes effect. Applied only on USB, only until the first real FileReceiving.
        _usbPreparingSilenceBound = service.TimeoutPolicy.PreparingSilenceBound;

        // #2197 (P0-D/P0-B): seed the version-exchange bound and the Preparing hard cap from the same
        // policy so the host keys UsbVersionExchangeBoundSec / UsbPreparingHardCapSec take effect.
        _usbVersionExchangeBound = service.TimeoutPolicy.VersionExchangeBound;
        _usbPreparingHardCap = service.TimeoutPolicy.PreparingHardCap;

        // #2197 (P0-E): one Info line of the EFFECTIVE transport policy at construction so any recurrence
        // is diagnosable in a single run without enabling Debug. Volume is one line per connection open.
        TransportTimeoutPolicy policy = service.TimeoutPolicy;
        _logger.LogInformation(
            "DeviceLink transport policy (usb={IsUsb}): sslWatchdog={SslSec}s interMsg={InterMsgSec}s preparing={PreparingSec}s preparingHardCap={HardCapSec}s versionExchange={VerSec}s read={ReadMs}ms",
            IsUsbTransport, policy.SslHandshakeWatchdogSec, policy.InterMessageSilenceBoundSec,
            policy.PreparingSilenceBoundSec, policy.PreparingHardCapSec, policy.VersionExchangeBoundSec,
            policy.ReadTimeoutMs);

        _internalCancellationTokenSource = new CancellationTokenSource();

        // ScribeHold fork (#2181): bind the response-guarantee owner to SendStatusReport. Every
        // handler that owes a DLMessageStatusResponse gets its terminating send through this single
        // path, so exactly-one-response (even under mid-handler cancellation) is enforced in one place.
        _responseGuarantees = new DeviceLinkResponseGuarantees(SendStatusReport);

        // Adjust the timeout to be long enough to handle device with a large amount of data
        _service.SetTimeout(SERVICE_READ_TIMEOUT_MS);

        DeviceLinkHandlers = new Dictionary<string, Func<ArrayNode, CancellationToken, Task>>() {
            { DeviceLinkMessage.ContentsOfDirectory, ContentsOfDirectory },
            { DeviceLinkMessage.CopyItem, CopyItem },
            { DeviceLinkMessage.CreateDirectory, CreateDirectory },
            { DeviceLinkMessage.Disconnect, DisconnectAsync },
            { DeviceLinkMessage.DownloadFiles, DownloadFiles },
            { DeviceLinkMessage.GetFreeDiskSpace, GetFreeDiskSpace },
            { DeviceLinkMessage.PurgeDiskSpace, GetFreeDiskSpace },
            { DeviceLinkMessage.MoveFiles, MoveItems },
            { DeviceLinkMessage.MoveItems, MoveItems },
            { DeviceLinkMessage.RemoveFiles, RemoveItems },
            { DeviceLinkMessage.RemoveItems, RemoveItems },
            { DeviceLinkMessage.UploadFiles, UploadFiles }
        };
    }

    /// <summary>
    /// ScribeHold fork (#2181): override the USB inter-message silence bound from the host
    /// configuration (BackupConfiguration.UsbInterMessageSilenceBoundSec, Task 3). The library carries
    /// a USB-tight default so it is safe standalone; when hosted, the real threshold originates in
    /// config and is applied here. A non-positive value is ignored (the library default is kept) so a
    /// misconfigured host can never disable the bound. Only affects USB transport; WiFi stays loose.
    /// </summary>
    public void SetUsbInterMessageSilenceBound(TimeSpan bound) {
        if (bound > TimeSpan.Zero) {
            _usbInterMessageSilenceBound = bound;
        }
    }

    /// <summary>
    /// ScribeHold fork (#2181): true when this device-link session runs over USB (usbmux), false for
    /// WiFi/network (TCP lockdown). The inter-message silence bound is applied ONLY on USB so the
    /// tight, feed-recovery behavior never regresses the loose WiFi loop timing. A pure-TCP connection
    /// (no MuxDevice) is treated as WiFi; a usbmux Network connection is likewise WiFi.
    /// </summary>
    private bool IsUsbTransport => _service.MuxDevice?.ConnectionType == Usbmuxd.UsbmuxdConnectionType.Usb;

    private void CloseFileStream() {
        try {
            _fileStream?.Flush();
        }
        catch (Exception fex) {
            _logger.LogError("Error flushing backup file: {message}", fex.Message);
        }
        _fileStream?.Close();
        _fileStream = null;
    }

    /// <summary>
    /// ScribeHold fork (data-corruption GATE, #2046): removes any pre-existing file at the given
    /// local path so the upcoming whole-file transfer replaces it instead of appending onto a stale
    /// partial left by an interrupted prior backup session. No-op when the path does not exist.
    /// Internal + static so the receive loop and the fork regression test exercise identical logic.
    /// </summary>
    internal static void DeleteStalePartial(string localPath) {
        if (!string.IsNullOrEmpty(localPath) && File.Exists(localPath)) {
            File.Delete(localPath);
        }
    }

    /// <summary>
    /// Manages the ListDirectory device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>Always 0.</returns>
    private async Task ContentsOfDirectory(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): the response-guarantee ensures exactly one terminating
        // DLMessageStatusResponse is sent even if cancellation trips mid-enumeration. The loop body
        // honors cancellation (ThrowIfCancellationRequested), and if that throws before the explicit
        // send below, the guarantee's DisposeAsync discharges the response on CancellationToken.None
        // before the OperationCanceledException propagates — the device is never left blocking.
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        string path = Path.Combine(_rootPath, msg[1].AsStringNode().Value);
        DictionaryNode dirList = [];
        DirectoryInfo dir = new DirectoryInfo(path);
        if (dir.Exists) {
            foreach (FileSystemInfo entry in dir.GetFileSystemInfos()) {
                cancellationToken.ThrowIfCancellationRequested();
                DictionaryNode entryDict = new DictionaryNode {
                    { "DLFileModificationDate", new DateNode(entry.LastWriteTime) },
                    { "DLFileSize", new IntegerNode(entry is FileInfo fileInfo ? fileInfo.Length : 0L) },
                    { "DLFileType", new StringNode(entry.Attributes.HasFlag(FileAttributes.Directory) ? "DLFileTypeDirectory" : "DLFileTypeRegular") }
                };
                dirList.Add(entry.Name, entryDict);
            }
        }

        await guard.SendTerminatingStatusAsync(0, null, dirList, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Manages the CopyItem device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>The errno result of the operation.</returns>
    private async Task CopyItem(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): route the terminating response through the guarantee so a throw
        // mid-copy still discharges exactly one DLMessageStatusResponse before propagating.
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        FileInfo source = new FileInfo(Path.Combine(_rootPath, msg[1].AsStringNode().Value));
        FileInfo dest = new FileInfo(Path.Combine(_rootPath, msg[2].AsStringNode().Value));
        if (source.Attributes.HasFlag(FileAttributes.Directory)) {
            _logger.LogError("Trying to coppy a whole directory rather than an individual file");
        }
        else {
            source.CopyTo(dest.FullName);
        }
        await guard.SendTerminatingStatusAsync(0, string.Empty, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Manages the CreateDirectory device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>The errno result of the operation.</returns>
    private async Task CreateDirectory(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): terminating response through the guarantee (exactly-once even on throw).
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        string newDirPath = Path.Combine(_rootPath, msg[1].AsStringNode().Value);
        Directory.CreateDirectory(newDirPath);
        await guard.SendTerminatingStatusAsync(0, string.Empty, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a dictionary plist instance of the required error report for the device.
    /// </summary>
    /// <param name="errorNo">The errno code.</param>
    private static DictionaryNode CreateErrorReport(ErrNo errorNo) {
        string errMsg;
        int errCode = -(int) errorNo;

        if (errorNo == ErrNo.ENOENT) {
            errCode = -6;
            errMsg = "No such file or directory.";
        }
        else if (errorNo == ErrNo.EEXIST) {
            errCode = -7;
            errMsg = "File or directory already exists.";
        }
        else {
            errMsg = $"Unspecified error: ({errorNo})";
        }

        DictionaryNode dict = new DictionaryNode() {
            { "DLFileErrorString", new StringNode(errMsg) },
            { "DLFileErrorCode", new IntegerNode(errCode) }
        };
        return dict;
    }

    private void Disconnect() {
        ArrayNode message = [
            new StringNode("DLMessageDisconnect"),
            new StringNode("___EmptyParameterString___")
        ];
        try {
            _service.SendPlist(message, PlistFormat.Binary);
        }
        catch (ObjectDisposedException) {
            _logger.LogWarning("Trying to send disconnect from disposed service");
        }
        catch (IOException ex) {
            // #2197 (P0-C): a broken/closed peer during the disconnect send is expected (the device may
            // have already FIN'd). Swallow it so Dispose stays unreachable-proof — the socket close in the
            // Dispose finally is what actually releases the transport.
            _logger.LogDebug(ex, "Disconnect send failed on a broken peer (ignored)");
        }
    }

    private async Task DisconnectAsync(ArrayNode msg, CancellationToken cancellationToken) {
        ArrayNode message = [
            new StringNode("DLMessageDisconnect"),
            new StringNode("___EmptyParameterString___")
        ];
        try {
            await _service.SendPlistAsync(message, PlistFormat.Binary, cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) {
            _logger.LogWarning("Trying to send disconnect from disposed service");
        }
    }

    /// <summary>
    /// Manages the DownloadFiles device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    private async Task DownloadFiles(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): the DLMessageStatusResponse at the end is what the device blocks on.
        // Route it through the guarantee so a cancellation mid-transfer still discharges exactly one
        // terminating response (on CancellationToken.None via DisposeAsync) before propagating.
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        DictionaryNode errList = [];
        ArrayNode files = msg[1].AsArrayNode();
        foreach (StringNode filename in files.Cast<StringNode>()) {
            _logger.LogDebug("Sending file: {filename}", filename);
            cancellationToken.ThrowIfCancellationRequested();
            await SendPath(filename.Value, cancellationToken).ConfigureAwait(false);

            string filePath = Path.Combine(_rootPath, filename.Value);
            if (File.Exists(filePath)) {
                await using (FileStream fs = File.OpenRead(filePath)) {
                    // We want to use a chunk size of 128 MiB
                    byte[] chunk = new byte[128 * 1024 * 1024];

                    int bytesRead;
                    while ((bytesRead = await fs.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0) {
                        byte[] data = [
                            (byte) ResultCode.FileData,
                            .. chunk[0 .. bytesRead]
                        ];
                        await SendPrefixed(data, data.Length, cancellationToken).ConfigureAwait(false);
                    }
                }

                byte[] buffer = [(byte) ResultCode.Success];
                await SendPrefixed(buffer, buffer.Length, cancellationToken).ConfigureAwait(false);
            }
            else {
                ErrNo errorCode = ErrNo.ENOENT;
                _logger.LogDebug("Sending Error Code: {code}", errorCode);
                DictionaryNode errReport = CreateErrorReport(errorCode);
                errList.Add(filename.Value, errReport);
                await SendError(errReport, cancellationToken).ConfigureAwait(false);
                OnSendFileError(errReport, filename.Value);
            }
        }

        await _service.SendAsync(BitConverter.GetBytes(FILE_TRANSFER_TERMINATOR), cancellationToken).ConfigureAwait(false);
        if (errList.Count == 0) {
            await guard.SendTerminatingStatusAsync(0, null, null, cancellationToken).ConfigureAwait(false);
        }
        else {
            await guard.SendTerminatingStatusAsync(BULK_OPERATION_ERROR, "Multi status", errList, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Manages the GetFreeDiskSpace device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <param name="respectFreeSpaceValue">Whether the device should abide by the freeSpace value passed or ignore it</param>
    /// <returns>0 on success, -1 on error.</returns>
    private async Task GetFreeDiskSpace(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): terminating response through the guarantee (exactly-once even on throw).
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        IntegerNode spaceItem = new IntegerNode(long.MaxValue);
        if (_performBackupSizeCheck) {
            long freeSpace = 0;
            DirectoryInfo dir = new DirectoryInfo(_rootPath);
            foreach (DriveInfo drive in DriveInfo.GetDrives()) {
                try {
                    if (drive.IsReady && drive.Name == dir.Root.FullName) {
                        freeSpace = drive.AvailableFreeSpace;
                        break;
                    }
                }
                catch (Exception ex) {
                    _logger.LogError(ex, "Issue getting space from drive");
                    Warning?.Invoke(this, new DetailedErrorEventArgs(ex, _rootPath));
                }
            }
            spaceItem = new IntegerNode(freeSpace);
        }
        await guard.SendTerminatingStatusAsync(0, null, spaceItem, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Manages the MoveItems device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>The number of items moved.</returns>
    private async Task MoveItems(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): the terminating DLMessageStatusResponse is guaranteed even if
        // cancellation trips mid-move — the loop body throws on cancel, and DisposeAsync discharges the
        // response on CancellationToken.None before propagating. Eliminates the wedge-source
        // if (!IsCancellationRequested) { send } ... break shape (device left blocking on cancel).
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        foreach (KeyValuePair<string, PropertyNode> move in msg[1].AsDictionaryNode()) {
            cancellationToken.ThrowIfCancellationRequested();

            string newPath = move.Value.AsStringNode().Value;
            if (!string.IsNullOrEmpty(newPath)) {
                FileInfo newFile = new FileInfo(Path.Combine(_rootPath, newPath));
                if (newFile.Exists) {
                    if (newFile.Attributes.HasFlag(FileAttributes.Directory)) {
                        new DirectoryInfo(newFile.FullName).Delete(true);
                    }
                    else {
                        newFile.Delete();
                    }
                }

                FileInfo oldFile = new FileInfo(Path.Combine(_rootPath, move.Key));
                if (oldFile.Exists) {
                    oldFile.MoveTo(newFile.FullName);
                }
            }
        }

        await guard.SendTerminatingStatusAsync(0, string.Empty, null, cancellationToken).ConfigureAwait(false);
    }

    private void OnSendFileError(DictionaryNode errorReport, string fileName) {
        SendFileError?.Invoke(errorReport, fileName);
    }

    /// <summary>
    /// Event handler called after a file has been received from the device.
    /// </summary>
    /// <param name="file">The file received.</param>
    private void OnFileReceived(BackupFile file) {
        if (_fileStream != null && Path.GetFileName(_fileStream.Name) == Path.GetFileName(file.LocalPath)) {
            try {
                CloseFileStream();
            }
            catch (Exception ex) {
                BackupFileErrorEventArgs e = new BackupFileErrorEventArgs(file, $"{ex.Message} : {ex.StackTrace}");
                FileTransferError?.Invoke(this, e);
            }
            finally {
                _fileStream = null;
            }
        }
        FileReceived?.Invoke(this, new BackupFileEventArgs(file));
    }

    /// <summary>
    /// Event handler called after a part (or all of) a file has been sent from the device from the device.
    /// </summary>
    /// <param name="file">The file received.</param>
    /// <param name="fileData">The file contents received</param>
    private void OnFileReceiving(BackupFile file, byte[] fileData) {
        // ScribeHold fork (#2193): latch the Preparing→in-transfer boundary. The FIRST FileReceiving is
        // the device beginning to push real backup-file content (mb2 UploadFiles); the Preparing-phase
        // manifest diff sends only DownloadFiles/ContentsOfDirectory, which never reach here. Once
        // latched, DlLoop switches from the generous Preparing bound to the tight inter-message bound.
        // Latch-once (never un-set) so a healthy in-transfer read never reverts to the generous bound.
        // #2197 (P0-E): log the transition exactly once — the moment real transfer begins is a key
        // diagnostic boundary (Preparing bound / hard-cap probe path ends here; the tight bound takes over).
        if (!_realTransferStarted) {
            _logger.LogInformation(
                "Preparing→Transfer: first real file transfer observed ({File}) — switching from the generous " +
                "Preparing bound to the tight in-transfer inter-message bound (#2197 P0-E)",
                Path.GetFileName(file.LocalPath));
        }
        _realTransferStarted = true;

        if (string.Equals("Status.plist", Path.GetFileName(file.LocalPath), StringComparison.OrdinalIgnoreCase)) {
            try {
                DictionaryNode statusPlist = PropertyList.LoadFromByteArray(fileData).AsDictionaryNode();
                OnStatusReceived(BackupStatus.ParsePlist(statusPlist, _logger));
            }
            catch (Exception ex) {
                BackupFileErrorEventArgs e = new BackupFileErrorEventArgs(file, $"{ex.Message} : {ex.StackTrace}");
                FileTransferError?.Invoke(this, e);
            }
        }
        FileReceiving?.Invoke(this, new BackupFileEventArgs(file, fileData));
    }

    /// <summary>
    /// Event handler called after a file transfer failed due to a device error.
    /// </summary>
    /// <param name="file">The file whose tranfer failed.</param>
    private void OnFileTransferError(BackupFile file, string details) {
        CloseFileStream();
        FailedFiles.Add(file);
        if (!_ignoreTransferErrors) {
            BackupFileErrorEventArgs e = new BackupFileErrorEventArgs(file, details);
            FileTransferError?.Invoke(this, e);
            _internalCancellationTokenSource.Cancel();
        }
    }

    /// <summary>
    /// Event handler called each time the backup service sends a status report.
    /// </summary>
    /// <param name="status">The status report sent from the backup service.</param>
    private void OnStatusReceived(BackupStatus status) {
        string snapshotState = $"{status.SnapshotState}";
        Status?.Invoke(this, new StatusEventArgs(snapshotState, status));
        _logger.LogDebug("OnStatus: {message}", snapshotState);

        // ScribeHold fork (#2081): latch the terminal Finished state. The device sends this in the
        // Status.plist transfer right before it expects the host to tear the connection down. When the
        // device instead holds the connection open (no FIN, no terminating DLMessageProcessMessage),
        // DlLoop consults this latch to do one short-timeout final read and complete gracefully rather
        // than blocking on the long read until it times out and fails (#2081). Latch-once: a backup
        // never transitions out of Finished, so this can only enable the short-read AFTER the terminal
        // state was actually observed.
        if (status.SnapshotState == SnapshotState.Finished) {
            _finishedObserved = true;
        }
    }

    private async Task<ResultCode> ReadCode(CancellationToken cancellationToken) {
        byte[] buffer = await _service.ReceiveAsync(1, cancellationToken).ConfigureAwait(false);
        byte code = buffer[0];
        if (!Enum.IsDefined(typeof(ResultCode), code)) {
            _logger.LogWarning("New backup code found: {code}", code);
        }
        return (ResultCode) code;
    }

    /// <summary>
    /// Reads an Int32 value from the backup service.
    /// </summary>
    /// <returns>The Int32 value read.</returns>
    private async Task<int> ReadInt32(CancellationToken cancellationToken) {
        byte[] buffer = await _service.ReceiveAsync(sizeof(int), cancellationToken).ConfigureAwait(false);
        if (buffer.Length > 0) {
            return EndianBitConverter.BigEndian.ToInt32(buffer, 0);
        }
        return -1;
    }

    /// <summary>
    /// Reads the information of the next file that the backup service will send.
    /// </summary>
    /// <returns>Returns the file information of the next file to download, or null if there are no more files to download.</returns>
    private async Task<BackupFile?> ReceiveBackupFile(CancellationToken cancellationToken) {
        string devicePath = await ReceiveFilename(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(devicePath)) {
            return null;
        }
        string backupPath = await ReceiveFilename(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(backupPath)) {
            _logger.LogWarning("Error reading backup file path.");
        }
        return new BackupFile(devicePath, backupPath, _rootPath);
    }

    /// <summary>
    /// Reads a filename from the backup service stream.
    /// </summary>>
    /// <returns>The filename read from the backup stream, or NULL if there are no more files.</returns>
    private async Task<string> ReceiveFilename(CancellationToken cancellationToken) {
        int len = await ReadInt32(cancellationToken).ConfigureAwait(false);
        if (len == 0) {
            // A zero length means no more files to receive.
            return string.Empty;
        }
        byte[] buffer = await _service.ReceiveAsync(len, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// Manages the RemoveItems device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>The number of items removed.</returns>
    private async Task RemoveItems(ArrayNode message, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): a single DLMessageRemoveItems/RemoveFiles message owes exactly ONE
        // terminating DLMessageStatusResponse (as in libimobiledevice's mb2_handle_remove_files, which
        // removes every item then sends one status at the end). The prior fork shape sent one status
        // PER item and, worse, break-ed out of the loop on cancellation WITHOUT sending the final
        // response — leaving the device blocked forever (the silent wedge). Route the single
        // terminating response through the guarantee: the loop body honors cancellation (throws), and
        // DisposeAsync discharges the response on CancellationToken.None before the cancellation
        // propagates, so exactly one response is always sent.
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        ArrayNode removes = message[1].AsArrayNode();
        foreach (StringNode filename in removes.Cast<StringNode>()) {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrEmpty(filename.Value)) {
                _logger.LogWarning("Empty file to remove.");
            }
            else {
                string path = Path.Combine(_rootPath, filename.Value);
                if (File.Exists(path)) {
                    File.Delete(path);
                }
                else if (Directory.Exists(path)) {
                    Directory.Delete(path, true);
                }
            }
        }

        await guard.SendTerminatingStatusAsync(0, string.Empty, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends the specified error report to the backup service.
    /// </summary>
    /// <param name="error">The error report to send.</param>
    public async Task SendError(DictionaryNode errorReport, CancellationToken cancellationToken) {
        byte[] errBytes = Encoding.UTF8.GetBytes(errorReport["DLFileErrorString"].AsStringNode().Value);
        List<byte> buffer = [
            (byte) ResultCode.LocalError, .. errBytes
        ];
        await SendPrefixed([.. buffer], buffer.Count, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a filename to the backup service stream.
    /// </summary>
    /// <param name="filename">The filename to send.</param>
    private async Task SendPath(string filename, CancellationToken cancellationToken) {
        byte[] path = Encoding.UTF8.GetBytes(filename);
        await SendPrefixed(path, path.Length, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendPrefixed(byte[] data, int length, CancellationToken cancellationToken) {
        await _service.SendAsync(EndianBitConverter.BigEndian.GetBytes(length), cancellationToken).ConfigureAwait(false);
        await _service.SendAsync(data, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a status report to the backup service.
    /// </summary>
    /// <param name="errorCode">The error code to send (as errno value).</param>
    /// <param name="errorMessage">The error message to send.</param>
    /// <param name="errorList">A PropertyNode with additional value(s).</param>
    private async Task SendStatusReport(int errorCode, string? errorMessage = null, PropertyNode? errorList = null, CancellationToken cancellationToken = default) {
        ArrayNode array = [
            new StringNode("DLMessageStatusResponse"),
            new IntegerNode(errorCode),
            !string.IsNullOrEmpty(errorMessage) ? new StringNode(errorMessage) : new StringNode("___EmptyParameterString___"),
            errorList ?? new DictionaryNode(),
        ];

        await _service.SendPlistAsync(array, PlistFormat.Binary, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Updates the progress as signaled by the backup service message.
    /// </summary>
    /// <param name="msg">The message received containing the progress information.</param>
    /// <param name="index">The index of the element in the array that contains the progress value.</param>
    private void UpdateProgressForMessage(RealNode progressNode) {
        if (progressNode.Value > 0.0) {
            Progress?.Invoke(this, new ProgressChangedEventArgs((int) progressNode.Value, BytesRead));
        }
    }

    /// <summary>
    /// Manages the UploadFiles device message.
    /// </summary>
    /// <param name="msg">The message received from the device.</param>
    /// <returns>The number of files processed.</returns>
    private async Task UploadFiles(ArrayNode msg, CancellationToken cancellationToken) {
        // ScribeHold fork (#2181): the terminating DLMessageStatusResponse after the transfer loop is
        // what the device blocks on. Route it through the guarantee so a cancellation that trips while
        // receiving files still discharges exactly one terminating response (on CancellationToken.None
        // via DisposeAsync) before propagating — the device is never left blocking.
        await using IDeviceLinkResponseGuarantee guard = _responseGuarantees.Create();

        long startTicks = DateTime.UtcNow.Ticks;

        long backupTotalSize = (long) msg[3].AsIntegerNode().Value;
        if (backupTotalSize > 0) {
            _logger.LogDebug("Backup total size: {backupTotalSize}", backupTotalSize);
        }

        while (!cancellationToken.IsCancellationRequested) {
            BackupFile? backupFile = await ReceiveBackupFile(cancellationToken).ConfigureAwait(false);
            if (backupFile != null) {
                // Ensure the directory requested exists before writing to it.
                string? pathDir = Path.GetDirectoryName(backupFile.LocalPath);
                if (!string.IsNullOrWhiteSpace(pathDir) && !Directory.Exists(backupFile.LocalPath)) {
                    Directory.CreateDirectory(pathDir);
                }

                backupFile.ExpectedFileSize = backupTotalSize;
                _logger.LogDebug("Receiving file {BackupPath}", backupFile.BackupPath);
                BeforeReceivingFile?.Invoke(this, new BackupFileEventArgs(backupFile));

                int size = await ReadInt32(cancellationToken).ConfigureAwait(false);
                ResultCode code = await ReadCode(cancellationToken).ConfigureAwait(false);
                size -= sizeof(ResultCode);

                // ScribeHold fork: classify once per file (at first chunk). If discarding, skip
                // File.OpenWrite and drain all chunks without writing. _fileStream stays null for
                // discarded files.
                if (_fileStream == null && !_discarding) {
                    _discarding = ShouldDiscardFile?.Invoke(backupFile.DevicePath) ?? false;
                    if (!_discarding) {
                        // ScribeHold fork (data-corruption GATE, #2046): delete any pre-existing
                        // file at the LocalPath before opening the write stream. When a prior backup
                        // session was interrupted mid-file, a partial copy can remain on disk; the
                        // device re-sends the WHOLE file. File.OpenWrite + Seek(End) below would
                        // APPEND the re-send onto that partial (partial bytes + full bytes), silently
                        // corrupting the backup. Removing the stale file first makes the re-send a
                        // clean replacement. Generalizes the prior Status.plist-only delete-guard to
                        // every file (BackupFile.LocalPath is deterministic). Only runs at the start
                        // of a new file (_fileStream == null) -- the in-session multi-chunk append
                        // path below (_fileStream != null) is untouched.
                        DeleteStalePartial(backupFile.LocalPath);
                        _fileStream = File.OpenWrite(backupFile.LocalPath);
                        _fileStream.Seek(0, SeekOrigin.End);
                    }
                }
                else if (_fileStream != null) {
                    _fileStream.Seek(0, SeekOrigin.End);
                }

                while (size > 0 && code == ResultCode.FileData) {
                    // ScribeHold fork: time the transfer receive and disk write separately so the
                    // caller can diagnose whether the backup is transfer-bound or disk-bound. We
                    // measure only the buffer-sized chunk transfers here (the dominant path);
                    // metadata ReadInt32/ReadCode calls are excluded as they are negligible.
                    long rxStart = Stopwatch.GetTimestamp();
                    byte[] buffer = await _service.ReceiveAsync(size, cancellationToken).ConfigureAwait(false);
                    long rxElapsed = Stopwatch.GetTimestamp() - rxStart;
                    Interlocked.Add(ref _rxBytes, buffer.Length);
                    Interlocked.Add(ref _rxTicks, rxElapsed);

                    if (!_discarding) {
                        long wxStart = Stopwatch.GetTimestamp();
                        await _fileStream!.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                        long wxElapsed = Stopwatch.GetTimestamp() - wxStart;
                        Interlocked.Add(ref _wxBytes, buffer.Length);
                        Interlocked.Add(ref _wxTicks, wxElapsed);
                    }

                    backupFile.FileSize += buffer.Length;
                    OnFileReceiving(backupFile, buffer);

                    size = await ReadInt32(cancellationToken).ConfigureAwait(false);
                    code = await ReadCode(cancellationToken).ConfigureAwait(false);
                    size -= sizeof(ResultCode);
                }

                if (code == ResultCode.RemoteError) {
                    byte[] msgBuffer = await _service.ReceiveAsync(size, cancellationToken).ConfigureAwait(false);
                    string errorMessage = Encoding.UTF8.GetString(msgBuffer);

                    _logger.LogWarning("Failed to fully upload {localPath}. Device file name {devicePath}. Reason: {msg}", backupFile.LocalPath, backupFile.DevicePath, errorMessage);
                    OnFileTransferError(backupFile, $"{code}: {msg} [ExpectedSize: {backupFile.ExpectedFileSize}, ActualReceived: {backupFile.FileSize} ]");
                    _discarding = false;

                    continue;
                }

                if (code == ResultCode.Success) {
                    if (_discarding) {
                        // Create zero-byte stub so Manifest.db references and subsequent incremental
                        // backup logic (File.Exists check) remain consistent.
                        using (File.Create(backupFile.LocalPath)) { }
                        _discarding = false;
                    }
                    OnFileReceived(backupFile);
                }
            }
            else if (_service.IsConnected) {
                break;
            }
            else {
                throw new DeviceDisconnectedException();
            }
        }

        await guard.SendTerminatingStatusAsync(0, null, null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// ScribeHold fork: returns cumulative receive/write throughput counters and resets them to
    /// zero. Intended for diagnostic logging at the end of a backup session to determine whether
    /// transfer time is dominated by the transfer receive or the disk write.
    /// </summary>
    public (long rxBytes, TimeSpan rxTime, long wxBytes, TimeSpan wxTime) GetAndResetThroughputStats() {
        long rxBytes = Interlocked.Exchange(ref _rxBytes, 0);
        long rxTicks = Interlocked.Exchange(ref _rxTicks, 0);
        long wxBytes = Interlocked.Exchange(ref _wxBytes, 0);
        long wxTicks = Interlocked.Exchange(ref _wxTicks, 0);
        var rxTime = TimeSpan.FromSeconds((double) rxTicks / Stopwatch.Frequency);
        var wxTime = TimeSpan.FromSeconds((double) wxTicks / Stopwatch.Frequency);
        return (rxBytes, rxTime, wxBytes, wxTime);
    }

    public void Dispose() {
        // #2197 (P0-C): wrap Disconnect in try/finally so _service.Close() ALWAYS runs even if the
        // DLMessageDisconnect send throws (previously a throwing Disconnect skipped Close and leaked the
        // socket). The socket close is the deterministic FIN and must be unreachable-proof.
        try {
            Disconnect();
        }
        finally {
            CloseAndDisposeCore();
        }
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-C): dispose WITHOUT sending DLMessageDisconnect — the quiet-abandon
    /// path. When we are unwinding on a drop-class the host will RESUME, sending Disconnect tells the busy
    /// device to tear down the very session we are about to resume; we must only close the socket
    /// (deterministic FIN) so backupd keeps holding the in-progress snapshot. The socket close and CTS
    /// dispose always run.
    /// </summary>
    public void DisposeQuietly() {
        CloseAndDisposeCore();
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-C): the shared close path — close the underlying service connection
    /// (the real TCP FIN via ServiceConnection.Close, which now disposes the socket-owning network
    /// stream) and dispose the internal CTS. Each step is independently guarded so one failure never
    /// skips the next, and the finalizer is always suppressed.
    /// </summary>
    private void CloseAndDisposeCore() {
        try {
            _service.Close();
        }
        finally {
            _internalCancellationTokenSource.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    public async Task<ResultCode> DlLoop(CancellationToken cancellationToken = default) {
        Started?.Invoke(this, new BackupStartedEventArgs(this._iosVersion));
        FailedFiles.Clear();
        // ScribeHold fork (#2081): reset the Finished latch per loop so a reused service instance never
        // carries a prior session's terminal state into a new backup.
        _finishedObserved = false;
        // ScribeHold fork (#2193): reset the real-transfer latch per loop for the same reason — a resumed
        // session starts back in the Preparing window (generous bound) until it re-observes real transfer.
        _realTransferStarted = false;

        _internalCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // ScribeHold fork (#2197, P0-E): per-exchange sequence counter for the DlLoop trace so a live run
        // is diagnosable in a single pass — each read is logged with seq#, command, elapsed and bytes.
        long dlLoopSeq = 0;
        while (!cancellationToken.IsCancellationRequested) {
            ArrayNode message;
            long readStartTicks = Stopwatch.GetTimestamp();
            if (_finishedObserved) {
                // ScribeHold fork (#2081): once SnapshotState=Finished has been observed, bound the next
                // read to a short timeout instead of the long SERVICE_READ_TIMEOUT_MS block. If the device
                // sends its terminating DLMessageProcessMessage it arrives well inside the bound and is
                // handled normally by the switch below; if the device instead holds the connection open
                // after finishing (no FIN, no final message — the desync this fixes), the short read times
                // out / returns empty and we complete gracefully as success. Finished is terminal, so this
                // can never prematurely complete a still-transferring backup.
                (message, bool finishedTimedOut) =
                    await ReceiveFinalMessageAfterFinished(_internalCancellationTokenSource.Token).ConfigureAwait(false);
                if (ShouldCompleteAfterFinished(finishedTimedOut, message.Count)) {
                    _logger.LogInformation(
                        "Backup reported SnapshotState=Finished and the connection was held open with no terminating message; completing gracefully (#2081)");
                    Completed?.Invoke(this, new BackupResultEventArgs(FailedFiles, false, false));
                    return ResultCode.Success;
                }
            }
            else {
                // ScribeHold fork (#2181/#2197): on USB, bound the wait for the next inter-message read to
                // a tight silence bound (seconds) instead of only the coarse ~10-minute
                // SERVICE_READ_TIMEOUT_MS. A device going silent BETWEEN messages then trips a bounded,
                // classifiable transport-drop signal (DeviceLinkInterMessageTimeoutException) that FEEDS
                // reconnect-and-resume, rather than wedging until the long read finally times out. WiFi
                // keeps its loose behavior (the bound is applied only on USB).
                //
                // #2197 (P0-B): during the pre-first-file Preparing window a trip is PROBED, not obeyed
                // blindly — a healthy multi-minute on-device manifest diff must not be torn down. When the
                // generous Preparing bound trips and the transport probes HEALTHY, we keep waiting under a
                // total-continuous hard cap; we tear down only on transport evidence (probe says dead) or
                // hard-cap exhaustion.
                message = await ReceiveMessageWithPreparingProbeAsync(_internalCancellationTokenSource.Token).ConfigureAwait(false);
                if (message.Count == 0) {
                    _logger.LogWarning("Received array node with no elements");
                    await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                    continue;
                }
            }

            string command = message[0].AsStringNode().Value;
            _logger.LogDebug("Command recieved: {command}", command);

            // ScribeHold fork (#2197, P0-E): one Info line per DlLoop exchange — seq#, command, response
            // status code (when the message carries one), element count and elapsed ms. Observed max
            // ~8 msg/s, so the volume is fine and a live wedge is diagnosable in a single run.
            double dlLoopElapsedMs = Stopwatch.GetElapsedTime(readStartTicks).TotalMilliseconds;
            long dlLoopStatus = ExtractStatusCode(command, message);
            _logger.LogInformation(
                "DlLoop exchange #{Seq}: command={Command} status={Status} elements={Count} elapsedMs={ElapsedMs:0.#}",
                ++dlLoopSeq, command, dlLoopStatus, message.Count, dlLoopElapsedMs);

            switch (command) {
                case DeviceLinkMessage.ProcessMessage: {
                    if (message[1].AsDictionaryNode()["ErrorCode"].AsIntegerNode().Value != (ulong) ResultCode.Success) {
                        throw new DeviceLinkException($"Device link error: {PropertyList.SaveAsString(message[1], PlistFormat.Xml)}");
                    }
                    Completed?.Invoke(this, new BackupResultEventArgs(FailedFiles, false, false));
                    return ResultCode.Success;
                }

                case DeviceLinkMessage.UploadFiles: {
                    UpdateProgressForMessage(message[2].AsRealNode());
                    break;
                }

                case DeviceLinkMessage.GetFreeDiskSpace: {
                    // We don't do anything specific for this, so just skip
                    break;
                }

                default: {
                    UpdateProgressForMessage(message[3].AsRealNode());
                    break;
                }
            }

            await DeviceLinkHandlers[command](message, _internalCancellationTokenSource.Token).ConfigureAwait(false);
        }
        return ResultCode.Skipped;
    }

    public async Task<ArrayNode> ReceiveMessage(CancellationToken cancellationToken) {
        PropertyNode? message = await _service.ReceivePlistAsync(cancellationToken).ConfigureAwait(false);
        if (message == null) {
            return [];
        }
        return message.AsArrayNode();
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-D): read a pre-DlLoop version-exchange message with the USB version-
    /// exchange bound applied. Used for the DLMessageVersionExchange read, the DLMessageDeviceReady read
    /// and the mb2 <c>Hello</c> response read — the three reads that, before this bound existed, went
    /// straight to the coarse ~10-minute stream read on a RESUMED session and let a busy-but-silent
    /// <c>backupd</c> dead-end the resume as fatal. On USB, if the device stays silent longer than
    /// <see cref="_usbVersionExchangeBound"/> this raises a
    /// <see cref="DeviceLinkVersionExchangeTimeoutException"/> (a bounded, classifiable transport-drop
    /// signal that FEEDS reconnect-and-resume) in seconds. On WiFi (or a non-positive bound) it defers to
    /// the plain <see cref="ReceiveMessage"/> with no added bound. A caller cancellation is always
    /// propagated, never reclassified.
    /// </summary>
    public Task<ArrayNode> ReceiveVersionExchangeMessage(CancellationToken cancellationToken) {
        return ReceiveWithVersionExchangeBoundAsync(
            IsUsbTransport, _usbVersionExchangeBound, ReceiveMessage, _logger, cancellationToken);
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-D): the transport-aware version-exchange bounded read, static with the
    /// read function injected so the TIMING behavior is unit-testable without a live socket. Mirrors
    /// <see cref="ReceiveWithInterMessageBoundAsync"/>: when the bound does not apply (WiFi, or a
    /// non-positive bound) it defers to <paramref name="read"/> with no added bound; when it applies (USB,
    /// positive bound) it raises a bounded <see cref="DeviceLinkVersionExchangeTimeoutException"/> if the
    /// bound elapses before a message arrives and the caller did NOT request cancellation. A genuine
    /// caller cancellation is always propagated as-is.
    /// </summary>
    internal static async Task<ArrayNode> ReceiveWithVersionExchangeBoundAsync(
        bool isUsbTransport,
        TimeSpan bound,
        Func<CancellationToken, Task<ArrayNode>> read,
        ILogger logger,
        CancellationToken cancellationToken) {
        if (!ShouldApplyInterMessageBound(isUsbTransport, bound)) {
            return await read(cancellationToken).ConfigureAwait(false);
        }

        using CancellationTokenSource versionExchangeCts = new CancellationTokenSource(bound);
        using CancellationTokenSource linkedCts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, versionExchangeCts.Token);
        try {
            return await read(linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (versionExchangeCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            // The USB version-exchange bound elapsed (not a caller cancellation): a busy-but-silent
            // backupd (typically a resumed session) never answered. Surface the bounded transport-drop
            // signal so the coordinator can reconnect-and-resume rather than wait out the long read.
            logger.LogWarning(
                "USB version-exchange bound ({BoundSec}s) tripped waiting on a device reply; surfacing a bounded transport-drop signal for reconnect-and-resume (#2197 P0-D)",
                bound.TotalSeconds);
            throw new DeviceLinkVersionExchangeTimeoutException(bound);
        }
    }

    /// <summary>
    /// ScribeHold fork (#2181): read the next inter-message DeviceLink message, applying the USB-tight
    /// inter-message silence bound. On USB, if the device stays silent between messages longer than
    /// <see cref="_usbInterMessageSilenceBound"/>, this raises a
    /// <see cref="DeviceLinkInterMessageTimeoutException"/> — a bounded, classifiable transport-drop
    /// signal that FEEDS reconnect-and-resume — in seconds, instead of blocking on the coarse
    /// ~10-minute stream read. On WiFi (or when the bound is non-positive) it defers to the plain
    /// <see cref="ReceiveMessage"/> path with no added bound, preserving loose WiFi loop timing. A
    /// genuine caller-requested cancellation is always propagated, never reclassified as an
    /// inter-message timeout.
    /// </summary>
    private Task<ArrayNode> ReceiveMessageWithInterMessageBound(CancellationToken cancellationToken) {
        // #2193: pre-first-file (Preparing) uses the generous bound so a healthy multi-minute manifest
        // diff finishes uninterrupted; once real transfer has started, the tight in-transfer bound governs.
        TimeSpan bound = SelectInterMessageBound(
            _realTransferStarted, _usbPreparingSilenceBound, _usbInterMessageSilenceBound);
        return ReceiveWithInterMessageBoundAsync(
            IsUsbTransport, bound, ReceiveMessage, _logger, cancellationToken);
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): read the next DlLoop message with the inter-message bound, but
    /// during the pre-first-file <c>Preparing</c> window a bound trip is PROBED rather than obeyed
    /// blindly. When the generous Preparing bound trips (device silent while it builds its on-device
    /// manifest diff), we run a passive transport health check — the socket-level poll plus the optional
    /// host-supplied <see cref="PresenceProbe"/>. If the transport is HEALTHY the device is still diffing,
    /// so we log Info and KEEP WAITING, re-entering the bounded read, until the TOTAL continuous Preparing
    /// silence exceeds the hard cap (<see cref="_usbPreparingHardCap"/>). We tear down (rethrow the bounded
    /// transport-drop signal) ONLY on transport evidence (probe says dead) or hard-cap exhaustion. TCP
    /// keepalive remains the true dead-peer detector; this adds a device-still-diffing tolerance on top.
    ///
    /// <para>Once real transfer has started the tight in-transfer bound governs and a trip is NOT probed —
    /// a mid-transfer stall is genuinely anomalous and feeds reconnect immediately (the #2181/#2193
    /// behavior is preserved). WiFi never applies the bound, so this whole path is USB-only.</para>
    /// </summary>
    private async Task<ArrayNode> ReceiveMessageWithPreparingProbeAsync(CancellationToken cancellationToken) {
        // The total continuous Preparing silence measured across probe iterations (the hard cap bounds
        // this, not a single probe interval). Started at the first trip and never reset while we keep
        // waiting in the Preparing window.
        long preparingSilenceStartTicks = 0;
        while (true) {
            try {
                return await ReceiveMessageWithInterMessageBound(cancellationToken).ConfigureAwait(false);
            }
            catch (DeviceLinkInterMessageTimeoutException interMessageTimeout) {
                // Only PROBE while still in the Preparing window on USB — a post-transfer stall or a WiFi
                // path must surface the signal immediately (unchanged behavior). _realTransferStarted may
                // have latched between reads; re-check it here so the boundary is honored precisely.
                if (_realTransferStarted || !IsUsbTransport) {
                    throw;
                }

                if (preparingSilenceStartTicks == 0) {
                    preparingSilenceStartTicks = Stopwatch.GetTimestamp();
                }
                TimeSpan totalSilence = Stopwatch.GetElapsedTime(preparingSilenceStartTicks) + interMessageTimeout.Bound;

                bool transportHealthy = await IsPreparingTransportHealthyAsync(cancellationToken).ConfigureAwait(false);
                if (ShouldContinuePreparingWait(transportHealthy, totalSilence, _usbPreparingHardCap)) {
                    _logger.LogInformation(
                        "Still preparing (device diffing), transport healthy — continuing to wait (#2197 P0-B). " +
                        "totalPreparingSilence={SilenceSec:0.#}s hardCap={HardCapSec:0.#}s",
                        totalSilence.TotalSeconds, _usbPreparingHardCap.TotalSeconds);
                    continue;
                }

                // Tear down: either the transport probe reported a dead peer, or the hard cap is exhausted.
                if (!transportHealthy) {
                    _logger.LogWarning(
                        "Preparing silence bound tripped and the transport probed DEAD — surfacing the bounded " +
                        "transport-drop signal for reconnect-and-resume (#2197 P0-B). totalPreparingSilence={SilenceSec:0.#}s",
                        totalSilence.TotalSeconds);
                }
                else {
                    _logger.LogWarning(
                        "Preparing hard cap exhausted ({HardCapSec:0.#}s) while the transport still probed healthy — " +
                        "surfacing the bounded transport-drop signal for reconnect-and-resume (#2197 P0-B). " +
                        "totalPreparingSilence={SilenceSec:0.#}s",
                        _usbPreparingHardCap.TotalSeconds, totalSilence.TotalSeconds);
                }
                throw;
            }
        }
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): the pure decision for whether the DlLoop keeps waiting on a
    /// Preparing-phase silence trip. Keep waiting only when the transport is healthy AND the total
    /// continuous Preparing silence is still within the hard cap. A dead transport, or an exhausted hard
    /// cap, both stop the wait so the bounded transport-drop signal surfaces. Pure + internal so the fork
    /// regression test exercises the boundary without a live socket or clock.
    /// </summary>
    internal static bool ShouldContinuePreparingWait(bool transportHealthy, TimeSpan totalPreparingSilence, TimeSpan hardCap) {
        return transportHealthy && totalPreparingSilence < hardCap;
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): the composite Preparing-phase transport health check — the passive
    /// socket-level probe AND (when the host has wired one) the optional <see cref="PresenceProbe"/>. The
    /// device is considered present only when BOTH agree it is alive; a socket-dead or presence-gone
    /// verdict means tear down. When no presence probe is supplied the socket probe alone decides. The
    /// presence probe is best-effort: if it throws, we treat presence as UNKNOWN and defer to the socket
    /// probe rather than letting a probe error fail the backup.
    /// </summary>
    private async Task<bool> IsPreparingTransportHealthyAsync(CancellationToken cancellationToken) {
        bool socketHealthy = _service.IsTransportHealthy();
        if (!socketHealthy) {
            return false;
        }

        DevicePresenceProbe? probe = PresenceProbe;
        if (probe == null) {
            return true;
        }
        try {
            return await probe(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) {
            throw;
        }
        catch (Exception ex) {
            // A presence-probe error must not fail the backup — defer to the socket probe (healthy here).
            _logger.LogWarning(ex, "Preparing presence probe threw; deferring to the socket probe (healthy) (#2197 P0-B)");
            return true;
        }
    }

    /// <summary>
    /// ScribeHold fork (#2193): the pure phase-selection for which silence bound the DlLoop applies to
    /// the next inter-message read. Before the first real backup-file transfer
    /// (<paramref name="realTransferStarted"/> == false) the device is in the <c>Preparing</c> window —
    /// building its on-device manifest diff — and is legitimately silent for MINUTES, so the generous
    /// <paramref name="preparingBound"/> applies. Once real transfer has begun a between-message gap is
    /// genuinely anomalous, so the tight <paramref name="inTransferBound"/> applies and a wedge is caught
    /// in seconds. Pure + internal so the fork regression test exercises the boundary without a live
    /// socket or clock.
    /// </summary>
    internal static TimeSpan SelectInterMessageBound(bool realTransferStarted, TimeSpan preparingBound, TimeSpan inTransferBound) {
        return realTransferStarted ? inTransferBound : preparingBound;
    }

    /// <summary>
    /// ScribeHold fork (#2181): the transport-aware inter-message bounded read, static with the read
    /// function injected so the TIMING behavior is unit-testable without a live socket. When the bound
    /// does not apply (WiFi, or a non-positive bound), it defers to <paramref name="read"/> with no
    /// added bound (loose WiFi loop timing preserved). When it applies (USB, positive bound), it bounds
    /// the wait: if the bound elapses before a message arrives — and the caller did NOT request
    /// cancellation — it raises a bounded <see cref="DeviceLinkInterMessageTimeoutException"/> in
    /// seconds (feeding reconnect-and-resume) instead of blocking on the coarse ~10-minute stream read.
    /// A genuine caller cancellation is always propagated as-is, never reclassified.
    /// </summary>
    internal static async Task<ArrayNode> ReceiveWithInterMessageBoundAsync(
        bool isUsbTransport,
        TimeSpan bound,
        Func<CancellationToken, Task<ArrayNode>> read,
        ILogger logger,
        CancellationToken cancellationToken) {
        if (!ShouldApplyInterMessageBound(isUsbTransport, bound)) {
            return await read(cancellationToken).ConfigureAwait(false);
        }

        using CancellationTokenSource interMessageCts = new CancellationTokenSource(bound);
        using CancellationTokenSource linkedCts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, interMessageCts.Token);
        try {
            return await read(linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (interMessageCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            // The USB inter-message bound elapsed (not a caller cancellation): the device went silent
            // between messages. Surface the bounded transport-drop signal so the coordinator can
            // reconnect-and-resume rather than wait out the long read.
            logger.LogWarning(
                "USB inter-message silence bound ({BoundSec}s) tripped between DeviceLink messages; surfacing a bounded transport-drop signal for reconnect-and-resume (#2181)",
                bound.TotalSeconds);
            throw new DeviceLinkInterMessageTimeoutException(bound);
        }
    }

    /// <summary>
    /// ScribeHold fork (#2181): the pure decision for whether the USB inter-message silence bound
    /// applies — true only on USB transport with a positive bound. WiFi (loose) and a non-positive
    /// (disabled) bound both return false so the plain read path with no added bound is used. Pure +
    /// internal so the fork regression test exercises the transport/bound gating without a live socket.
    /// </summary>
    internal static bool ShouldApplyInterMessageBound(bool isUsbTransport, TimeSpan bound) {
        return isUsbTransport && bound > TimeSpan.Zero;
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-E): extract the response status code carried by a DlLoop message for
    /// the per-exchange trace. Only DLMessageProcessMessage carries an <c>ErrorCode</c> dictionary entry;
    /// every other command has no status field, so <see cref="long.MinValue"/> is returned as a sentinel
    /// ("n/a"). Best-effort and exception-safe — a diagnostic trace must never throw into the loop. Pure +
    /// internal so the fork regression test can exercise it without a live socket.
    /// </summary>
    internal static long ExtractStatusCode(string command, ArrayNode message) {
        const long noStatus = long.MinValue;
        if (command != DeviceLinkMessage.ProcessMessage || message.Count < 2) {
            return noStatus;
        }
        try {
            DictionaryNode body = message[1].AsDictionaryNode();
            if (body.TryGetValue("ErrorCode", out PropertyNode? errorCode)) {
                return (long) errorCode.AsIntegerNode().Value;
            }
        }
        catch (Exception) {
            // A malformed body must not break the trace — fall through to the sentinel.
        }
        return noStatus;
    }

    /// <summary>
    /// ScribeHold fork (#2081): the pure decision for the post-Finished read — complete the backup
    /// gracefully as success when the short final read either timed out (<paramref name="finishedTimedOut"/>)
    /// or returned an empty message (<paramref name="messageCount"/> == 0). Both mean the device reported
    /// the terminal Finished state and then sent nothing more on the held-open connection. A non-empty
    /// message (<paramref name="messageCount"/> &gt; 0) within the bound is a real terminating message and
    /// is handled by the normal switch instead. Pure + internal so the fork regression test exercises the
    /// exact branch logic without a live socket.
    /// </summary>
    internal static bool ShouldCompleteAfterFinished(bool finishedTimedOut, int messageCount) {
        return finishedTimedOut || messageCount == 0;
    }

    /// <summary>
    /// ScribeHold fork (#2081): the post-Finished final read. Reads the next DeviceLink message with a
    /// short <see cref="FINISHED_FINAL_READ_TIMEOUT_MS"/> bound rather than the long
    /// <see cref="SERVICE_READ_TIMEOUT_MS"/> stream block, so a device that has already reported the
    /// terminal Finished state but holds the connection open (no FIN, no terminating message) releases
    /// the loop in ~5 s instead of blocking ~10 min and then failing.
    /// </summary>
    /// <param name="cancellationToken">The loop's (internal-linked) cancellation token.</param>
    /// <returns>
    /// The received message and a flag: <c>finishedTimedOut == true</c> when the short bound elapsed
    /// (or the stream itself surfaced a timeout / a 0-byte FIN with no plist) — i.e. the device finished
    /// but sent nothing more, so the loop should complete gracefully. When a real message arrives within
    /// the bound the flag is <c>false</c> and the message is handled normally (e.g. the terminating
    /// DLMessageProcessMessage). A genuine caller-requested cancellation is rethrown, never swallowed.
    /// </returns>
    private async Task<(ArrayNode message, bool finishedTimedOut)> ReceiveFinalMessageAfterFinished(CancellationToken cancellationToken) {
        using CancellationTokenSource finalReadTimeoutCts = new CancellationTokenSource(FINISHED_FINAL_READ_TIMEOUT_MS);
        using CancellationTokenSource linkedCts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, finalReadTimeoutCts.Token);
        try {
            ArrayNode message = await ReceiveMessage(linkedCts.Token).ConfigureAwait(false);
            return (message, false);
        }
        catch (OperationCanceledException) when (finalReadTimeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            // Short bound elapsed: the device finished but sent nothing more on the held-open connection.
            return ([], true);
        }
        catch (TimeoutException) {
            // The underlying ServiceConnection stream read timed out (the device finished and went silent
            // without closing) — same conclusion as the short bound elapsing.
            return ([], true);
        }
    }

    public async Task SendProcessMessage(PropertyNode message, CancellationToken cancellationToken) {
        await _service.SendPlistAsync(
            new ArrayNode() {
                new StringNode("DLMessageProcessMessage"),
                message
            },
            PlistFormat.Binary,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <summary>
    /// Performs the DLMessageVersionExchange with the connected device. 
    /// This should be the first operation to be executed by an implemented
    /// device link service client.
    /// </summary>
    /// <param name="versionMajor">The major version number to check.</param>
    /// <param name="versionMinor">The minor version number to check.</param>
    public async Task VersionExchange(ulong versionMajor, ulong versionMinor, CancellationToken cancellationToken) {
        // ScribeHold fork (#2068): this is the exact step where the "empty-reply-FIN" wedge bites.
        // Trace each sub-step with elapsed-ms timing (Debug-gated, free when off) so a live failure
        // self-explains: FIN-before-reply vs partial vs malformed plist, and WHERE the ~1s wedge
        // diverges from a healthy ~fast handshake.
        bool diag = _logger.IsEnabled(LogLevel.Debug);
        Stopwatch stopwatch = diag ? Stopwatch.StartNew() : new Stopwatch();

        // ScribeHold fork (#2077): arm the service-channel plaintext dump for the version-exchange
        // window ONLY. While armed, a 0-byte/short read on the mb2 channel (the FIN point) dumps the
        // decrypted partial bytes + classifies close_notify-vs-RST. We disarm in the finally below the
        // moment version exchange ends, BEFORE the transfer phase carries user content on the same SSL
        // stream. We also log the host's DLVersionExchange offer (the supported version the host WOULD
        // send in DLVersionsOk) so a USB-vs-WiFi diff can compare what each transport offers (AC4).
        _service.BeginVersionExchangeWindow();
        if (diag) {
            _logger.LogDebug(
                "DeviceLink VersionExchange: host DLVersionExchange offer (would send DLVersionsOk {Major}.{Minor}); hostBytesSentBeforeFirstRead={HostBytesSent}",
                versionMajor, versionMinor, _service.HostBytesSent);
        }
        try {
            await VersionExchangeCore(versionMajor, versionMinor, diag, stopwatch, cancellationToken).ConfigureAwait(false);
        }
        finally {
            // ScribeHold fork (#2077): close the dump window — the transfer phase that follows carries
            // user message content and must never be dumped.
            _service.EndVersionExchangeWindow();
        }
    }

    /// <summary>
    /// ScribeHold fork (#2077): the body of <see cref="VersionExchange"/>, extracted so the
    /// version-exchange plaintext-dump window can be opened/closed around it with a try/finally
    /// without nesting the whole flow. Behavior is identical to the prior inline body.
    /// </summary>
    private async Task VersionExchangeCore(ulong versionMajor, ulong versionMinor, bool diag, Stopwatch stopwatch, CancellationToken cancellationToken) {
        if (diag) {
            _logger.LogDebug("DeviceLink VersionExchange: awaiting DLMessageVersionExchange from device (expect {Major}.{Minor})", versionMajor, versionMinor);
        }

        // Get DLMessageVersionExchange from device
        // #2197 (P0-D): bounded read — a busy-but-silent backupd on a resumed session must feed reconnect
        // in seconds, not wait the coarse ~10-minute stream read and then dead-end as fatal.
        ArrayNode versionExchangeMessage = await ReceiveVersionExchangeMessage(cancellationToken);
        if (diag) {
            _logger.LogDebug(
                "DeviceLink VersionExchange: received {Count}-element message after {ElapsedMs}ms: {Message}",
                versionExchangeMessage.Count, stopwatch.ElapsedMilliseconds, DescribePlist(versionExchangeMessage));
        }
        if (versionExchangeMessage.Count < 3) {
            // FIN-before-reply / malformed: ReceiveMessage returns [] when ReceivePlistAsync read 0 bytes.
            throw new DeviceLinkException("DLMessageVersionExchange has unexpected format (size < 3)");
        }

        string dlMessage = versionExchangeMessage[0].AsStringNode().Value;
        if (string.IsNullOrEmpty(dlMessage) || dlMessage != "DLMessageVersionExchange") {
            throw new DeviceLinkException("Didn't receive DLMessageVersionExchange from device");
        }

        // Get major and minor version number
        ulong vMajor = versionExchangeMessage[1].AsIntegerNode().Value;
        ulong vMinor = versionExchangeMessage[2].AsIntegerNode().Value;
        if (vMajor > versionMajor) {
            throw new DeviceLinkException($"Version mismatch detected received {vMajor}.{vMinor}, expected {versionMajor}.{versionMinor}");
        }
        else if (vMajor == versionMajor && vMinor > versionMinor) {
            throw new DeviceLinkException($"Version mismatch detected received {vMajor}.{vMinor}, expected {versionMajor}.{versionMinor}");
        }

        // The version is ok so send reply
        if (diag) {
            _logger.LogDebug("DeviceLink VersionExchange: device offered {Major}.{Minor}; sending DLVersionsOk at {ElapsedMs}ms", vMajor, vMinor, stopwatch.ElapsedMilliseconds);
        }
        _service.SendPlist(new ArrayNode {
            new StringNode("DLMessageVersionExchange"),
            new StringNode("DLVersionsOk"),
            new IntegerNode(versionMajor)
        }, PlistFormat.Binary);

        // Receive DeviceReady message
        if (diag) {
            _logger.LogDebug("DeviceLink VersionExchange: awaiting DLMessageDeviceReady at {ElapsedMs}ms", stopwatch.ElapsedMilliseconds);
        }
        // #2197 (P0-D): bounded read for the same reason as the DLMessageVersionExchange read above.
        ArrayNode messageDeviceReady = await ReceiveVersionExchangeMessage(cancellationToken);
        if (diag) {
            _logger.LogDebug(
                "DeviceLink VersionExchange: received {Count}-element reply after {ElapsedMs}ms: {Message}",
                messageDeviceReady.Count, stopwatch.ElapsedMilliseconds, DescribePlist(messageDeviceReady));
        }
        if (messageDeviceReady.Count == 0) {
            // FIN after our DLVersionsOk reply but before DeviceReady — the device accepted the
            // version but tore down the connection (distinct from the pre-reply FIN above).
            throw new DeviceLinkException("Device link didn't return ready state (DLMessageDeviceReady); received empty reply");
        }
        dlMessage = messageDeviceReady[0].AsStringNode().Value;
        if (string.IsNullOrEmpty(dlMessage) || dlMessage != "DLMessageDeviceReady") {
            throw new DeviceLinkException("Device link didn't return ready state (DLMessageDeviceReady)");
        }
        if (diag) {
            _logger.LogDebug("DeviceLink VersionExchange: completed (DeviceReady) in {ElapsedMs}ms", stopwatch.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// ScribeHold fork (#2068): render a DeviceLink array message as a compact, log-safe string for
    /// the diagnostic trace. The first element (the DLMessage* type tag) is the discriminator we care
    /// about; an empty array means a 0-byte/FIN read returned nothing.
    /// </summary>
    private static string DescribePlist(ArrayNode message) {
        if (message.Count == 0) {
            return "<empty / 0-byte read>";
        }
        try {
            return string.Join(", ", message.Select(static n => n switch {
                StringNode s => $"\"{s.Value}\"",
                IntegerNode i => i.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                _ => n.GetType().Name
            }));
        }
        catch (Exception) {
            return $"<{message.Count} elements>";
        }
    }
}
