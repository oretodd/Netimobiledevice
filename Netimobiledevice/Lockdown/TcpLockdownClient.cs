using Microsoft.Extensions.Logging;
using Netimobiledevice.Lockdown.Pairing;
using Netimobiledevice.Plist;
using Netimobiledevice.Usbmuxd;
using System.IO;
using System.Threading.Tasks;

namespace Netimobiledevice.Lockdown;

public class TcpLockdownClient : LockdownClient
{
    /// <summary>
    /// Read timeout (ms) for the WiFi lockdown CONTROL channel — bounds the synchronous plist reads
    /// (QueryType / GetValue / StartService) so an idle/unresponsive WiFi lockdown socket fails fast
    /// instead of wedging the backup worker thread forever (#1926). 30s is generous for a control
    /// round-trip on a healthy LAN; the bulk mobilebackup2 data channel is a separate connection and
    /// is unaffected.
    /// </summary>
    private const int ControlReadTimeoutMs = 30000;

    private readonly string _hostname;

    public TcpLockdownClient(ServiceConnection service, string hostId, string hostname = "", string identifier = "", string label = DEFAULT_CLIENT_NAME,
        string systemBuid = SYSTEM_BUID, DictionaryNode? pairRecord = null, DirectoryInfo? pairingRecordsCacheDirectory = null, ushort port = SERVICE_PORT,
        ILogger? logger = null) : base(service, hostId, identifier, label, systemBuid, pairRecord, pairingRecordsCacheDirectory, port, logger)
    {
        _hostname = hostname;
        ConnectionType = UsbmuxdConnectionType.Network;
    }

    public override ServiceConnection CreateServiceConnection(ushort port)
    {
        return ServiceConnection.CreateUsingTcp(_hostname, port, Logger);
    }

    public override async Task<ServiceConnection> CreateServiceConnectionAsync(ushort port)
    {
        return await ServiceConnection.CreateUsingTcpAsync(_hostname, port, Logger).ConfigureAwait(false);
    }

    /// <summary>
    /// Create a LockdownClient instance
    /// </summary>
    /// <param name="service">lockdownd connection handler</param>
    /// <param name="identifier">Used as an identifier to look for the device pair record</param>
    /// <param name="systemBuid">System's unique identifier</param>
    /// <param name="label">lockdownd user-agent</param>
    /// <param name="autopair">Attempt to pair with device (blocking) if not already paired</param>
    /// <param name="pairTimeout">Timeout for autopair</param>
    /// <param name="localHostname">Used as a seed to generate the HostID</param>
    /// <param name="pairRecord">Use this pair record instead of the default behavior (search in host/create our own)</param>
    /// <param name="pairingRecordsCacheFolder">Use the following location to search and save pair records</param>
    /// <param name="port">lockdownd service port</param>
    /// <returns>A new LockdownClient instance</returns>
    public static TcpLockdownClient Create(ServiceConnection service, string hostname = "", string identifier = "", string systemBuid = SYSTEM_BUID, string label = DEFAULT_CLIENT_NAME,
        bool autopair = true, float? pairTimeout = null, string localHostname = "", DictionaryNode? pairRecord = null, string pairingRecordsCacheFolder = "",
        ushort port = SERVICE_PORT, ILogger? logger = null)
    {
        string hostId = PairRecords.GenerateHostId(localHostname);
        DirectoryInfo? pairingRecordsCacheDirectory = PairRecords.GetPairingRecordsCacheFolder(pairingRecordsCacheFolder);

        // Bound the lockdown CONTROL-channel reads for WiFi (TCP). The control plist exchanges
        // (QueryType, GetValue, StartService) use a synchronous Stream.Read with no timeout, so when a
        // WiFi device's lockdown socket goes idle/unresponsive after the connect — e.g. the StartService
        // request for mobilebackup2 — the backup worker thread blocks FOREVER and the backup wedges in
        // Backup_Initializing with no passcode (ScribeHold #1926). A finite ReadTimeout makes such a
        // stalled control read throw (IOException) so the attempt fails fast and retries instead of
        // hanging. This is the CONTROL channel only: the separate mobilebackup2 DATA ServiceConnection
        // (returned by StartLockdownService) is NOT a TcpLockdownClient and keeps its long
        // keepalive budget for multi-minute bulk-transfer reads (#1857), so this does not truncate backups.
        service.SetTimeout(ControlReadTimeoutMs);

        TcpLockdownClient lockdownClient = new(service, hostId: hostId, hostname: hostname, identifier: identifier, label: label, systemBuid: systemBuid, pairRecord: pairRecord,
            pairingRecordsCacheDirectory: pairingRecordsCacheDirectory, port: port, logger: logger);

        lockdownClient.HandleAutoPair(autopair, pairTimeout ?? -1);
        return lockdownClient;
    }
}
