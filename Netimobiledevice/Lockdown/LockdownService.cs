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

            // Try the device's IPv4 (A-record) address FIRST, then IPv6. On a Wi-Fi NIC with no working
            // IPv6 route (the owner's machine — #1923) every IPv6 connect to the device's fe80::/fd8d::
            // AAAA address fails immediately with WSAENETUNREACH (10051), and the routable IPv4 A record
            // (192.168.68.x — the prototype proved the device answers IPv4 on Wi-Fi and a lockdown connect
            // to 192.168.68.88:62078 succeeds) was never reached / tried last. Ordering IPv4 first makes the
            // routable address the first attempt; IPv6 remains a fallback for hosts that DO have IPv6 on the
            // mDNS interface. A stable ordered copy is logged so a "no IPv4 candidate" case is visible.
            List<Address> ordered = OrderIpv4First(answer.Addresses);
            logger.LogDebug("mobdev2 device {Instance} connect candidates (IPv4-first): [{Candidates}]",
                answer.Instance, string.Join(", ", ordered.ConvertAll(a => a.FullIp)));

            foreach (Address address in ordered) {
                // Use FullIp, not Ip: iOS advertises mobdev2 on an IPv6 LINK-LOCAL address (fe80::...),
                // which is unroutable without its zone index. Address.FullIp appends "%<interface>" for
                // fe80: addresses so the socket can scope it; connecting to the bare Ip fails with an
                // invalid-argument / no-route error (ScribeHold #1914). The zone-scoped endpoint is also
                // what we yield, so the backup path reconnects to the same scoped address. (IPv4 A records
                // have no zone, so FullIp returns the bare routable address — what we want.)
                string endpoint = address.FullIp;
                TcpLockdownClient lockdown;
                try {
                    lockdown = MobileDevice.CreateUsingTcp(hostname: endpoint, autopair: false, pairRecord: record);
                }
                catch (Exception ex) {
                    // The TCP lockdown connect/handshake to a matched, advertised device failed (e.g. an
                    // IPv6 candidate on a NIC with no IPv6 route => WSAENETUNREACH). KEEP TRYING the
                    // remaining candidates — the next one may be the routable IPv4 address — instead of
                    // letting the first failure abort the device (#1923).
                    logger.LogInformation(ex, "mobdev2 device {Instance} at {Endpoint} matched but TCP lockdown connect failed; trying next candidate",
                        answer.Instance, endpoint);
                    continue;
                }

                if (onlyPaired && !lockdown.IsPaired) {
                    logger.LogDebug("mobdev2 device {Instance} at {Endpoint} connected but is not paired; skipping",
                        answer.Instance, endpoint);
                    lockdown.Close();
                    continue;
                }
                logger.LogDebug("mobdev2 device {Instance} reachable at {Endpoint}", answer.Instance, endpoint);
                yield return (endpoint, lockdown);
            }
        }

        // Outcome summary: how the browsed advertisements resolved. matched=0 with seen>0 is the
        // tell-tale of the WiFiMACAddress mismatch — paired devices ARE advertising but no on-disk
        // record's WiFi MAC matches them (ScribeHold #1905).
        logger.LogInformation(
            "mobdev2 sweep result: {AdvertisementsMatched} matched, {AdvertisementsUnmatched} unmatched of {AdvertisementsSeen} advertisement(s)",
            advertisementsMatched, advertisementsUnmatched, advertisementsSeen);
    }

    /// <summary>
    /// Return the addresses ordered IPv4 first, then IPv6, preserving the original relative order within
    /// each family (stable). On a Wi-Fi NIC with no IPv6 route the IPv4 A record is the only routable
    /// candidate, so it must be attempted before the unreachable fe80::/fd8d:: AAAA addresses (#1923).
    /// IPv4 vs IPv6 is decided by the presence of ':' in the address string (IPv6 contains colons; an
    /// IPv4 dotted-quad does not), avoiding an IPAddress.Parse of the already-zone-scoped FullIp.
    /// </summary>
    private static List<Address> OrderIpv4First(List<Address> addresses) {
        List<Address> v4 = [];
        List<Address> v6 = [];
        foreach (Address a in addresses) {
            if (a.Ip.Contains(':')) {
                v6.Add(a);
            }
            else {
                v4.Add(a);
            }
        }
        v4.AddRange(v6);
        return v4;
    }
}
