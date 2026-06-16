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

        // Per-sweep diagnostic counters. A zero-result sweep was previously silent, so "nothing is
        // advertising on the LAN" was indistinguishable from "everything advertising was skipped".
        // These are logged as a single summary line after the browse so the cause of a 0-device sweep
        // is visible in the log (ScribeHold #1905).
        int recordsLoaded = 0;
        int recordsSkippedNoMac = 0;
        int advertisementsSeen = 0;
        int advertisementsMatched = 0;
        int advertisementsUnmatched = 0;

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
                recordsSkippedNoMac++;
                logger.LogDebug("Skipping pair record {RecordUdid}: no WiFiMACAddress key present", recordUdid);
                continue;
            }

            records[wiFiMACAddressNode.AsStringNode().Value] = record;
            recordsLoaded++;
        }

        List<ServiceInstance> advertisements = await BonjourService.BrowseMobdev2Async(timeout, logger).ConfigureAwait(false);
        // One summary line per sweep makes the failure mode diagnosable: 0 advertisements => nothing
        // is broadcasting mobdev2 on the LAN; advertisements > matched => paired records are missing
        // the WiFiMACAddress key (or the keys disagree). recordsSkippedNoMac surfaces Apple-written
        // records that carry no WiFi MAC and so can never match (ScribeHold #1905).
        logger.LogInformation(
            "mobdev2 sweep: {RecordsLoaded} matchable pair record(s), {RecordsSkippedNoMac} skipped (no WiFiMACAddress), {AdvertisementsSeen} advertisement(s) browsed",
            recordsLoaded, recordsSkippedNoMac, advertisements.Count);

        foreach (ServiceInstance answer in advertisements) {
            if (!answer.Instance.Contains('@')) {
                continue;
            }
            advertisementsSeen++;
            // The mobdev2 instance name is "<wifiMacAddress>@<host>". Split on '@' and take the MAC;
            // Split('@')[0] (no count limit) is required — a count of 1 would return the whole string.
            string wifiMacAddress = answer.Instance.Split('@')[0];

            // No on-disk pair record matched this advertisement's WiFi MAC. Treat absence as
            // "not a paired device we know" and skip the advertisement instead of indexing the
            // dictionary (which would throw KeyNotFoundException). Honours onlyPaired for free.
            if (!records.TryGetValue(wifiMacAddress, out DictionaryNode? record)) {
                advertisementsUnmatched++;
                logger.LogDebug("Skipping mobdev2 advertisement {Instance}: no matching pair record", answer.Instance);
                continue;
            }

            advertisementsMatched++;
            // A matched advertisement with NO addresses means the SRV/A resolution did not complete
            // within the browse window — the device is advertising and paired, but we have no IP to
            // connect to. Surface that explicitly; it is otherwise an invisible dead-end.
            if (answer.Addresses.Count == 0) {
                logger.LogInformation(
                    "mobdev2 advertisement {Instance} matched a pair record but resolved no IP address (SRV/A not received in time)",
                    answer.Instance);
            }

            foreach (Address address in answer.Addresses) {
                TcpLockdownClient lockdown;
                try {
                    lockdown = MobileDevice.CreateUsingTcp(hostname: address.Ip, autopair: false, pairRecord: record);
                }
                catch (Exception ex) {
                    // The TCP lockdown connect/handshake to a matched, advertised device failed. This was
                    // previously swallowed silently, hiding a "matched but cannot connect" failure mode
                    // (wrong port, unreachable IP, handshake reject) behind a zero-device sweep.
                    logger.LogInformation(ex, "mobdev2 device {Instance} at {Endpoint} matched but TCP lockdown connect failed",
                        answer.Instance, address.Ip);
                    continue;
                }

                if (onlyPaired && !lockdown.IsPaired) {
                    logger.LogDebug("mobdev2 device {Instance} at {Endpoint} connected but is not paired; skipping",
                        answer.Instance, address.Ip);
                    lockdown.Close();
                    continue;
                }
                logger.LogDebug("mobdev2 device {Instance} reachable at {Endpoint}", answer.Instance, address.Ip);
                yield return (address.Ip, lockdown);
            }
        }

        // Outcome summary: how the browsed advertisements resolved. matched=0 with seen>0 is the
        // tell-tale of the WiFiMACAddress mismatch — paired devices ARE advertising but no on-disk
        // record's WiFi MAC matches them (ScribeHold #1905).
        logger.LogInformation(
            "mobdev2 sweep result: {AdvertisementsMatched} matched, {AdvertisementsUnmatched} unmatched of {AdvertisementsSeen} advertisement(s)",
            advertisementsMatched, advertisementsUnmatched, advertisementsSeen);
    }
}
