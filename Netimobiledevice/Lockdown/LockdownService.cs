using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Plist;
using Netimobiledevice.Remoted.Bonjour;
using System;
using System.Collections.Generic;
using System.IO;

namespace Netimobiledevice.Lockdown;

public abstract class LockdownService : IDisposable {
    protected LockdownServiceProvider Lockdown { get; }
    /// <summary>
    /// The internal logger
    /// </summary>
    protected ILogger Logger { get; }
    protected ServiceConnection Service { get; }
    protected string ServiceName { get; }

    /// <summary>
    /// Create a new LockdownService instance
    /// </summary>
    /// <param name="lockdown">Service provider</param>
    /// <param name="serviceName">The service name to attempt to connect to</param>
    /// <param name="service">An established service connection, if none we will attempt connecting to the provided serviceName</param>
    /// <param name="useEscrowBag">Use the available lockdown escrow back to start the service</param>
    public LockdownService(LockdownServiceProvider lockdown, string serviceName, ServiceConnection? service = null, bool useEscrowBag = false, ILogger? logger = null) {
        Lockdown = lockdown;
        Logger = logger ?? NullLogger.Instance;
        ServiceName = serviceName;
        Service = service ?? lockdown.StartLockdownService(ServiceName, useEscrowBag);
    }

    /// <summary>
    /// Create a new LockdownService instance
    /// </summary>
    /// <param name="lockdown">Service provider</param>
    /// <param name="lockdownServiceName">The service name to attempt to connect to if we have a Lockdown connection</param>
    /// <param name="rsdServiceName">The service name to attempt to connect to if we have an RSD connection</param>
    /// <param name="service">An established service connection, if none we will attempt connecting to the provided serviceName</param>
    /// <param name="useEscrowBag">Use the available lockdown escrow back to start the service</param>
    public LockdownService(LockdownServiceProvider lockdown, string lockdownServiceName, string rsdServiceName, ServiceConnection? service = null, bool useEscrowBag = false, ILogger? logger = null) {
        if (lockdown is LockdownClient) {
            ServiceName = lockdownServiceName;
        }
        else {
            ServiceName = rsdServiceName;
        }

        Lockdown = lockdown;
        Logger = logger ?? NullLogger.Instance;
        Service = service ?? lockdown.StartLockdownService(ServiceName, useEscrowBag);
    }

    public void Close() {
        Service.Close();
    }

    public virtual void Dispose() {
        Close();
        GC.SuppressFinalize(this);
    }

    public static async IAsyncEnumerable<(string, TcpLockdownClient)> GetMobdev2Lockdowns(
        string? udid = null,
        string? pairRecordsPath = null,
        bool onlyPaired = false,
        int timeout = BonjourService.DEFAULT_BONJOUR_TIMEOUT,
        ILogger? logger = null
    ) {
        logger ??= NullLogger.Instance;

        Dictionary<string, DictionaryNode> records = [];
        DirectoryInfo pairRecordsDirectory = new DirectoryInfo(pairRecordsPath ?? "");
        foreach (FileInfo file in pairRecordsDirectory.GetFiles("*.plist")) {
            if (file.Name.StartsWith("remote_", StringComparison.InvariantCulture)) {
                // Skip RemotePairing records
                continue;
            }

            string recordUdid = file.Name.Replace(".plist", "");
            if (udid != null && recordUdid != udid) {
                continue;
            }

            DictionaryNode record = PropertyList.LoadFromByteArray(File.ReadAllBytes(file.FullName)).AsDictionaryNode();

            // A pair record without a WiFiMACAddress cannot be matched to a mobdev2 advertisement
            // (the Bonjour instance name is keyed on the device's WiFi MAC). Skip it rather than
            // throwing KeyNotFoundException — only this one keyless record is dropped; every record
            // that DOES carry the key still resolves normally.
            if (!record.TryGetValue("WiFiMACAddress", out PropertyNode? wiFiMACAddressNode)) {
                logger.LogDebug("Skipping pair record {RecordUdid}: no WiFiMACAddress key present", recordUdid);
                continue;
            }

            records[wiFiMACAddressNode.AsStringNode().Value] = record;
        }

        foreach (ServiceInstance answer in await BonjourService.BrowseMobdev2Async(timeout).ConfigureAwait(false)) {
            if (!answer.Instance.Contains('@')) {
                continue;
            }
            // The mobdev2 instance name is "<wifiMacAddress>@<host>". Split on '@' and take the MAC;
            // Split('@')[0] (no count limit) is required — a count of 1 would return the whole string.
            string wifiMacAddress = answer.Instance.Split('@')[0];

            // No on-disk pair record matched this advertisement's WiFi MAC. Treat absence as
            // "not a paired device we know" and skip the advertisement instead of indexing the
            // dictionary (which would throw KeyNotFoundException). Honours onlyPaired for free.
            if (!records.TryGetValue(wifiMacAddress, out DictionaryNode? record)) {
                logger.LogDebug("Skipping mobdev2 advertisement {Instance}: no matching pair record", answer.Instance);
                continue;
            }

            foreach (Address address in answer.Addresses) {
                TcpLockdownClient lockdown;
                try {
                    lockdown = MobileDevice.CreateUsingTcp(hostname: address.Ip, autopair: false, pairRecord: record);
                }
                catch (Exception) {
                    continue;
                }

                if (onlyPaired && !lockdown.IsPaired) {
                    lockdown.Close();
                    continue;
                }
                yield return (address.Ip, lockdown);
            }
        }
    }
}
