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

        // Two views of the on-disk pair records: MAC -> UDID (the fast advertisement match) and UDID ->
        // record (every loadable record, the source of truth used by both paths and the identity-probe
        // fallback). A record is kept in recordsByUdid even when it has no WiFiMACAddress, because the
        // fallback can still identify the device by connecting with it — the MAC key is only the fast index.
        Dictionary<string, string> macToUdid = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, DictionaryNode> recordsByUdid = [];
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
            recordsByUdid[recordUdid] = record;

            // A pair record without a WiFiMACAddress cannot be matched to a mobdev2 advertisement by the
            // FAST path (the Bonjour instance name is keyed on the device's WiFi MAC). It is still kept in
            // recordsByUdid for the identity-probe fallback. Skip only the MAC-index insert rather than
            // throwing KeyNotFoundException.
            if (!record.TryGetValue("WiFiMACAddress", out PropertyNode? wiFiMACAddressNode)) {
                recordsSkippedNoMac++;
                logger.LogDebug("Pair record {RecordUdid}: no WiFiMACAddress key (fast match skipped; eligible for identity-probe fallback)", recordUdid);
                continue;
            }

            macToUdid[wiFiMACAddressNode.AsStringNode().Value] = recordUdid;
            recordsLoaded++;
        }

        // UDIDs already resolved this sweep (via fast MAC match or the identity probe), so the probe does
        // not re-test a record that the fast path already consumed and a device is not yielded twice.
        HashSet<string> resolvedUdids = new(StringComparer.OrdinalIgnoreCase);

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

            // IPv4-first candidate endpoints for this advertisement (see OrderIpv4First). On a Wi-Fi NIC
            // with no IPv6 route every fe80::/fd8d:: connect throws WSAENETUNREACH; ordering IPv4 first
            // makes the routable A record (192.168.68.x) the first attempt (#1923).
            List<Address> ordered = OrderIpv4First(answer.Addresses);

            if (macToUdid.TryGetValue(wifiMacAddress, out string? matchedUdid)
                && recordsByUdid.TryGetValue(matchedUdid, out DictionaryNode? record)) {
                // FAST PATH: the advertisement's WiFi MAC matches an on-disk pair record's WiFiMACAddress.
                advertisementsMatched++;
                if (answer.Addresses.Count == 0) {
                    logger.LogInformation(
                        "mobdev2 advertisement {Instance} matched a pair record but resolved no IP address (SRV/A not received in time)",
                        answer.Instance);
                }
                logger.LogDebug("mobdev2 device {Instance} connect candidates (IPv4-first): [{Candidates}]",
                    answer.Instance, string.Join(", ", ordered.ConvertAll(a => a.FullIp)));

                (string Endpoint, TcpLockdownClient Client)? hit = TryConnectWithRecord(ordered, record, matchedUdid, answer.Instance, onlyPaired, logger);
                if (hit is { } h) {
                    resolvedUdids.Add(matchedUdid);
                    yield return (h.Endpoint, h.Client);
                }
                continue;
            }

            // FALLBACK: no record's WiFiMACAddress matches this advertisement. This is the normal case for
            // an iOS device using PRIVATE WI-FI ADDRESS (MAC randomization): the device advertises mobdev2
            // with its randomized per-network Wi-Fi MAC, while the pair record stores the HARDWARE MAC
            // (read over lockdown as WiFiAddress), so the two never match (verified on a real device:
            // toddfone advertises ce:dd:a6:... but its pair record's WiFiMACAddress is 58:66:6d:... — #1923).
            // The device IS paired; we just cannot identify it by MAC. Identify it instead by PROBING: try
            // each not-yet-resolved pair record against the advertised IPv4 endpoint — the record whose
            // lockdown handshake succeeds (no GetProhibited) is this device. MAC-free, works over Wi-Fi.
            advertisementsUnmatched++;
            if (ordered.Count == 0) {
                logger.LogDebug("mobdev2 advertisement {Instance}: no pair record matched the MAC and no address to identity-probe", answer.Instance);
                continue;
            }
            logger.LogInformation(
                "mobdev2 advertisement {Instance}: WiFi MAC matched no pair record (likely iOS Private Wi-Fi Address); identity-probing {Count} pair record(s) against the advertised endpoint",
                answer.Instance, recordsByUdid.Count);

            (string Endpoint, TcpLockdownClient Client)? probed = null;
            foreach ((string candidateUdid, DictionaryNode candidateRecord) in recordsByUdid) {
                if (resolvedUdids.Contains(candidateUdid)) {
                    continue; // already yielded this device this sweep
                }
                probed = TryConnectWithRecord(ordered, candidateRecord, candidateUdid, answer.Instance, onlyPaired, logger);
                if (probed is { } p) {
                    resolvedUdids.Add(candidateUdid);
                    advertisementsMatched++;
                    logger.LogInformation(
                        "mobdev2 advertisement {Instance} identity-probed to pair record {Udid} at {Endpoint} (Private Wi-Fi Address match)",
                        answer.Instance, candidateUdid, p.Endpoint);
                    yield return (p.Endpoint, p.Client);
                    break;
                }
            }
            if (probed is null) {
                logger.LogDebug("mobdev2 advertisement {Instance}: identity probe matched no pair record", answer.Instance);
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
    /// <summary>
    /// Try to open a lockdown connection to <paramref name="orderedAddresses"/> (IPv4-first) using
    /// <paramref name="record"/> as the pair record (autopair disabled), and VERIFY the connected device's
    /// UDID matches <paramref name="expectedUdid"/>. Returns the first endpoint that connects, verifies, and
    /// (if <paramref name="onlyPaired"/>) is paired; null if none succeed. Used by both the fast MAC-match
    /// path and the identity-probe fallback.
    /// <para>
    /// The UDID verification is ESSENTIAL for the identity probe: with <c>autopair:false</c> the lockdown
    /// CONSTRUCTOR succeeds for any reachable device regardless of which pair record is supplied (the
    /// pairing is only exercised by a session-requiring call). The discriminator is a session-gated read:
    /// <c>GetValue("UniqueDeviceID")</c> returns the real UDID only when the record is valid for THAT device
    /// and throws <c>GetProhibited</c> for a foreign record (verified on a real device — #1923). So probing
    /// record R against an advertised endpoint must read the UDID and confirm it equals R's UDID; a bare
    /// successful construct is NOT proof of identity.
    /// </para>
    /// A per-address/per-record failure (WSAENETUNREACH on IPv6, GetProhibited on a foreign record, or a
    /// UDID mismatch) is logged and the next candidate is tried — never aborts the sweep.
    /// </summary>
    private static (string Endpoint, TcpLockdownClient Client)? TryConnectWithRecord(
        List<Address> orderedAddresses, DictionaryNode record, string expectedUdid, string instance, bool onlyPaired, ILogger logger) {
        foreach (Address address in orderedAddresses) {
            // FullIp scopes an fe80:: address with its zone (#1914); IPv4 A records return the bare IP.
            string endpoint = address.FullIp;
            TcpLockdownClient lockdown;
            try {
                lockdown = MobileDevice.CreateUsingTcp(hostname: endpoint, autopair: false, pairRecord: record);
            }
            catch (Exception ex) {
                logger.LogInformation(ex, "mobdev2 device {Instance} at {Endpoint} lockdown connect failed; trying next candidate",
                    instance, endpoint);
                continue;
            }

            // Verify identity: a session-gated UDID read confirms the pair record is valid for THIS device.
            // Throws GetProhibited for a foreign record; returns the device's UDID otherwise.
            string actualUdid;
            try {
                actualUdid = lockdown.GetValue("UniqueDeviceID")?.AsStringNode().Value ?? string.Empty;
            }
            catch (Exception ex) {
                logger.LogDebug(ex, "mobdev2 device {Instance} at {Endpoint}: pair record not valid for this device (identity read prohibited); trying next candidate",
                    instance, endpoint);
                lockdown.Close();
                continue;
            }

            if (!string.IsNullOrEmpty(expectedUdid) &&
                !string.Equals(actualUdid, expectedUdid, StringComparison.OrdinalIgnoreCase)) {
                logger.LogDebug("mobdev2 device {Instance} at {Endpoint}: connected device UDID {Actual} != record UDID {Expected}; trying next candidate",
                    instance, endpoint, actualUdid, expectedUdid);
                lockdown.Close();
                continue;
            }

            if (onlyPaired && !lockdown.IsPaired) {
                logger.LogDebug("mobdev2 device {Instance} at {Endpoint} connected but is not paired; skipping",
                    instance, endpoint);
                lockdown.Close();
                continue;
            }
            logger.LogDebug("mobdev2 device {Instance} reachable at {Endpoint}", instance, endpoint);
            return (endpoint, lockdown);
        }
        return null;
    }

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
