using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Remoted.Bonjour;

internal class MdnsBrowser : IDisposable {
    private const string MdnsMulticastV4 = "224.0.0.251";
    private const string MdnsMulticastV6 = "ff02::fb";

    // One receive/send socket per network interface, instead of a single IPAddress.Any:5353 socket joined
    // on every interface. The single-ANY-socket design made RECEIVE delivery depend on the Windows
    // multicast-binding order: on a host with a low-metric VPN/virtual adapter (Tailscale 100.124.x — the
    // owner's "if 32") the stack delivered the group's datagrams via the winning interface only, so the
    // physical Wi-Fi NIC's inbound adverts were dropped and every sweep saw "0 advertisements" while
    // `dns-sd` (a socket per interface) saw the device fine (ScribeHold #1917). Binding one socket per
    // interface makes each receive ONLY the datagrams arriving on ITS interface, independent of any other
    // adapter's metric, and the arrival interface is then known exactly (it is the socket's interface) with
    // no source-IP/subnet heuristic. SendQuery fans the query out of each socket the same way.
    // The per-interface sockets, plus the interface snapshot they were built from. Both are REBUILT on a
    // network change (NordLynx/Wi-Fi reconnect), so they are guarded by _socketsLock against the receive/
    // send loop that iterates them on a background thread (ScribeHold #1923 self-heal). A monotonically
    // increasing _socketGeneration tags each rebuild so the "first packet on if X" diagnostic fires once
    // per interface PER generation (a dead-on-arrival join that later heals is then visible in the log).
    private readonly object _socketsLock = new();
    private List<MdnsInterfaceSocket> _sockets = [];
    private NetworkInterface[] _interfaces;
    private int _socketGeneration;
    private readonly HashSet<string> _firstPacketLogged = [];
    // This host's OWN unicast addresses (all up interfaces). A multicast query we send loops back to every
    // joined socket as a "self-echo" with one of these as its source IP. Self-echoes must NOT count as a
    // device response: the dead-join detector keys off FOREIGN packets only, otherwise an interface that
    // hears only its own echoes looks "alive" and a churn loop forms (ScribeHold #1924). Rebuilt each
    // generation under _socketsLock alongside _sockets.
    private readonly HashSet<IPAddress> _localAddresses = [];
    private readonly ILogger _logger;

    /// <summary>
    /// Raised after the socket set has been rebuilt (e.g. on a network change), so a long-lived driver
    /// such as <see cref="PersistentMdnsBrowser"/> can break out of its current receive window and
    /// re-snapshot the new sockets immediately rather than waiting out the window on dead sockets.
    /// </summary>
    internal event Action? SocketsRebound;

    public MdnsBrowser(ILogger? logger = null) {
        _logger = logger ?? NullLogger.Instance;
        _interfaces = [.. NetworkInterface.GetAllNetworkInterfaces()];
        lock (_socketsLock) {
            BindInterfaceSockets();
        }
    }

    /// <summary>
    /// Tear down the current socket set and rebuild it from a FRESH <see cref="NetworkInterface"/> snapshot,
    /// re-running the same per-interface bind/join logic. This is the self-heal for a multicast join that was
    /// made while an interface (NordLynx/Wi-Fi) was mid-(re)connect and so stayed dead forever on that
    /// interface (ScribeHold #1923): a one-time ctor snapshot never recovered. Thread-safe against the
    /// receive/send loop via <see cref="_socketsLock"/>; raises <see cref="SocketsRebound"/> so the driver
    /// re-snapshots immediately.
    /// </summary>
    public void RebindSockets() {
        lock (_socketsLock) {
            _logger.LogInformation("rebinding mDNS sockets due to network change (generation {Gen} -> {Next})",
                _socketGeneration, _socketGeneration + 1);
            foreach (MdnsInterfaceSocket sock in _sockets) {
                sock.Dispose();
            }
            _sockets = [];
            _firstPacketLogged.Clear();
            _socketGeneration++;
            _interfaces = [.. NetworkInterface.GetAllNetworkInterfaces()];
            BindInterfaceSockets();
        }
        SocketsRebound?.Invoke();
    }

    /// <summary>Snapshot the current sockets under the lock for the receive/send loop to iterate safely.</summary>
    private (MdnsInterfaceSocket[] Sockets, int Generation) SnapshotSockets() {
        lock (_socketsLock) {
            return ([.. _sockets], _socketGeneration);
        }
    }

    private void BindInterfaceSockets() {
        IPAddress groupV4 = IPAddress.Parse(MdnsMulticastV4);
        IPAddress groupV6 = IPAddress.Parse(MdnsMulticastV6);

        var v4Bound = new List<string>();
        var v6Bound = new List<int>();

        // Rebuild the set of this host's own unicast addresses so received self-echoes can be told apart
        // from real device responses (ScribeHold #1924).
        _localAddresses.Clear();
        foreach (NetworkInterface ni in _interfaces) {
            if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast) {
                continue;
            }
            foreach (UnicastIPAddressInformation uni in ni.GetIPProperties().UnicastAddresses) {
                // Store the bare address (scope-id stripped for IPv6) so a self-echo source like
                // fe80::...%26 still matches our unicast fe80::... Equality on IPAddress ignores ScopeId
                // for comparison only when the bytes match; normalise by mapping to a scopeless copy.
                _localAddresses.Add(Scopeless(uni.Address));
            }
        }

        foreach (NetworkInterface ni in _interfaces) {
            if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast) {
                continue;
            }

            IPInterfaceProperties props = ni.GetIPProperties();

            // IPv4: one socket per IPv4 unicast address on this interface, joined on that address.
            foreach (UnicastIPAddressInformation uni in props.UnicastAddresses) {
                if (uni.Address.AddressFamily != AddressFamily.InterNetwork) {
                    continue;
                }
                MdnsInterfaceSocket? sock = MdnsInterfaceSocket.TryCreateV4(ni, uni.Address, groupV4, _logger);
                if (sock != null) {
                    _sockets.Add(sock);
                    v4Bound.Add($"{ni.Name}={uni.Address}");
                }
            }

            // IPv6: one socket per interface, joined on the REAL OS index. An interface with no IPv6 stack
            // (e.g. the owner's Wi-Fi NIC — #1914 round 6) throws on GetIPv6Properties() and is skipped; that
            // is fine because the device is reached over IPv4 there.
            int v6Index;
            try {
                v6Index = props.GetIPv6Properties().Index;
            }
            catch (Exception ex) {
                _logger.LogTrace(ex, "mDNS IPv6 per-interface socket skipped on {Interface} (no IPv6 properties)", ni.Name);
                continue;
            }
            MdnsInterfaceSocket? sockV6 = MdnsInterfaceSocket.TryCreateV6(ni, v6Index, groupV6, _logger);
            if (sockV6 != null) {
                _sockets.Add(sockV6);
                v6Bound.Add(v6Index);
            }
        }

        if (_sockets.Count == 0) {
            // No per-interface socket could be bound (no up+multicast interface with an address). Fall back
            // to a default-interface IPv4 socket so a degenerate single-NIC/permissions case still works.
            _logger.LogWarning("mDNS: no per-interface socket bound; falling back to default-interface IPv4 socket");
            MdnsInterfaceSocket? fallback = MdnsInterfaceSocket.TryCreateV4Default(groupV4, _logger);
            if (fallback != null) {
                _sockets.Add(fallback);
            }
        }

        // List the ACTUAL bound interfaces (not just a count) so a real-device log confirms the physical
        // Wi-Fi NIC's LAN address / index is among them — the decisive check for ScribeHold #1917: if the
        // device advertises on the Wi-Fi subnet but that address is not in this list, the bind itself is the
        // fault, not delivery.
        _logger.LogInformation("mDNS bound IPv4 socket(s) on: [{V4}]; IPv6 socket(s) on if: [{V6}]",
            string.Join(", ", v4Bound), string.Join(", ", v6Bound));
    }

    private void ParseMdnsMessage(byte[] data, long arrivalInterfaceIndex, IMdnsRecordSink sink) {
        if (data.Length < 12) {
            return;
        }

        int qdCount = (data[4] << 8) | data[5];
        int anCount = (data[6] << 8) | data[7];
        int nsCount = (data[8] << 8) | data[9];
        int arCount = (data[10] << 8) | data[11];
        int offset = 12;

        for (int i = 0; i < qdCount; i++) {
            (string _, int newOffset) = DnsHelpers.DecodeName(data, offset);
            offset = newOffset + 4;
        }

        // Walk EVERY record section — ANSWER, AUTHORITY and ADDITIONAL. mDNS responders routinely put the
        // SRV/TXT/A records for a browsed PTR in the ADDITIONAL section (known-answer suppression), so a
        // parser that stopped at anCount would see the PTR but miss its SRV/A and never resolve the
        // instance (ScribeHold #1914 round 7). anCount+nsCount+arCount covers all three.
        for (int i = 0; i < anCount + nsCount + arCount; i++) {
            offset = ParseRR(data, offset, arrivalInterfaceIndex, sink);
        }
    }

    private int ParseRR(byte[] data, int offset, long arrivalInterfaceIndex, IMdnsRecordSink sink) {
        (string? name, int newOffset) = DnsHelpers.DecodeName(data, offset);
        offset = newOffset;

        if (offset + 10 > data.Length) {
            return offset;
        }
        ushort rtype = (ushort) ((data[offset] << 8) | data[offset + 1]);
        ushort rclass = (ushort) ((data[offset + 2] << 8) | data[offset + 3]);
        // TTL is a 32-bit field at offset+4..+7. It drives the record cache's expiry; a TTL of 0 is an
        // mDNS "goodbye" that evicts the record (ScribeHold #1914 round 7 — devices leaving the LAN).
        uint ttl = (uint) ((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]);
        ushort rdlen = (ushort) ((data[offset + 8] << 8) | data[offset + 9]);
        offset += 10;

        if (offset + rdlen > data.Length) {
            return offset;
        }
        // Record the rdata's START OFFSET within the FULL packet before copying it out. PTR/SRV targets use
        // DNS name compression (RFC 1035 §4.1.4) whose pointers reference offsets in the WHOLE message, not
        // within the isolated rdata slice — so the target MUST be decoded against `data` from rdataStart,
        // never against a copied `rdata` array. Decoding from the slice loses the compression pointer and
        // yields a bare "." target that never resolves (verified on real devices, VPN on: every SRV came
        // back as ".:32498" until this was fixed). The `rdata` copy is still used for TXT/A/AAAA, whose
        // rdata is self-contained (no compression).
        int rdataStart = offset;
        byte[] rdata = new byte[rdlen];
        Array.Copy(data, offset, rdata, 0, rdlen);
        offset += rdlen;

        if (rtype == DnsHelpers.QTYPE_PTR) {
            (string? target, int _) = DnsHelpers.DecodeName(data, rdataStart);
            sink.AddPtr(name, target, ttl);
        }
        else if (rtype == DnsHelpers.QTYPE_SRV && rdlen >= 6) {
            ushort port = (ushort) ((rdata[4] << 8) | rdata[5]);
            // Priority(2)+Weight(2)+Port(2) precede the target name at rdataStart+6 in the full packet.
            (string? target, int _) = DnsHelpers.DecodeName(data, rdataStart + 6);
            sink.AddSrv(name, new Service(target, port), ttl);
        }
        else if (rtype == DnsHelpers.QTYPE_TXT) {
            var dict = new Dictionary<string, string>();
            int idx = 0;
            while (idx < rdlen) {
                int len = rdata[idx++];
                if (idx + len > rdlen) {
                    break;
                }
                string txt = Encoding.UTF8.GetString(rdata, idx, len);
                idx += len;
                string[] parts = txt.Split('=', 2);
                dict[parts[0]] = parts.Length == 2 ? parts[1] : "";
            }
            sink.AddTxt(name, dict, ttl);
        }
        else if ((rtype == DnsHelpers.QTYPE_A && rdlen == 4) ||
                 (rtype == DnsHelpers.QTYPE_AAAA && rdlen == 16)) {
            IPAddress ip = new IPAddress(rdata);

            // For a link-local IPv6 advert, the CORRECT zone is the interface the advert ARRIVED on — and
            // with per-interface sockets that index is exact (the receiving socket's interface), not a
            // source-IP guess. A device's fe80::... is only reachable via the NIC that received it; using a
            // different interface's index produces an unreachable "fe80::...%wrong" and the lockdown connect
            // fails. When the arrival index is known, use it; otherwise fall back to subnet/interface
            // matching. PickInterfaceForIp still serves IPv4 (returns the interface name) and the
            // unknown-arrival case.
            string iface;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal && arrivalInterfaceIndex >= 0) {
                iface = arrivalInterfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            else {
                iface = PickInterfaceForIp(ip);
            }

            // ALWAYS record the address — including IPv6 link-local (fe80::). Real iOS devices advertise
            // mobdev2 with ONLY an IPv6 link-local AAAA record (verified via dns-sd, #1914), so dropping
            // link-local would resolve every such device to zero connectable addresses. The zone index is
            // carried by Address.FullIp ("fe80::...%iface"); the scope above supplies the matching
            // local interface so the scope is correct. An empty iface is still recorded (best effort)
            // rather than discarded — discarding here is exactly what broke WiFi discovery.
            sink.AddAddress(name, new Address(ip.ToString(), iface), ttl);
            _logger.LogDebug("mDNS {Type} {Ip} for {Name} on interface '{Interface}' (ttl {Ttl}s)",
                ip.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A", ip, name, iface, ttl);
        }

        return offset;
    }

    /// <summary>
    /// Finds the local interface that can reach <paramref name="ip"/> and returns the zone token to use
    /// in a scoped address. For IPv6 this is the interface INDEX (the zone Windows requires in
    /// "fe80::...%index"); for IPv4 it is the interface name (informational — IPv4 has no zone).
    /// Returns empty if no local interface matches. Used as the fallback when the exact arrival interface
    /// is not available (e.g. an IPv4 A record, which carries no zone).
    /// </summary>
    private string PickInterfaceForIp(IPAddress ip) {
        foreach (NetworkInterface ni in _interfaces) {
            IPInterfaceProperties props = ni.GetIPProperties();
            foreach (UnicastIPAddressInformation uni in props.UnicastAddresses) {
                if (uni.Address.AddressFamily != ip.AddressFamily) {
                    continue;
                }
                if (ip.AddressFamily == AddressFamily.InterNetwork) {
                    uint ipInt = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
                    uint uniInt = BitConverter.ToUInt32(uni.Address.GetAddressBytes(), 0);
                    uint maskInt = BitConverter.ToUInt32(uni.IPv4Mask.GetAddressBytes(), 0);
                    if ((ipInt & maskInt) == (uniInt & maskInt)) {
                        return ni.Name;
                    }
                }
                else if (ip.IsIPv6LinkLocal) {
                    // The zone for a link-local IPv6 address is the interface index, and the device's
                    // advertised link-local is reachable on any interface that itself has a link-local
                    // address. Return the index so Address.FullIp produces a Windows-valid "fe80::...%N".
                    try {
                        return ni.GetIPProperties().GetIPv6Properties().Index
                            .ToString(System.Globalization.CultureInfo.InvariantCulture);
                    }
                    catch {
                        // Interface has no IPv6 properties — keep scanning.
                    }
                }
            }
        }
        return string.Empty;
    }

    /// <summary>
    /// Discover a DNS-SD/mDNS service type (e.g. "_remoted._tcp.local.") on the local network in a single
    /// time-bounded sweep. Used by the one-shot Bonjour browse paths (RemoteD, RemotePairing, Tunneld)
    /// that are NOT polled in a tight loop. For the mobdev2 discovery path, which IS polled every few
    /// seconds, prefer <see cref="PersistentMdnsBrowser"/> — its cross-sweep record cache resolves
    /// instances whose PTR/SRV/A arrive across different windows (ScribeHold #1914 round 7).
    /// </summary>
    /// <param name="serviceType"></param>
    /// <param name="timeout"></param>
    /// <returns>List of ServiceInstance with Address(ip, interface) entries.</returns>
    public async Task<List<ServiceInstance>> BrowseService(string serviceType, int timeout) {
        if (!serviceType.EndsWith('.')) {
            serviceType += ".";
        }

        byte[] query = DnsHelpers.BuildQuery(serviceType, DnsHelpers.QTYPE_PTR);
        await SendQuery(query).ConfigureAwait(false);
        _logger.LogDebug("mDNS PTR query sent for {ServiceType} (timeout {Timeout}ms)", serviceType, timeout);

        // A per-browse sink that accumulates this sweep's records (single-window semantics, unchanged
        // for the one-shot callers).
        SweepRecordSink sink = new();

        // timeout is MILLISECONDS (DEFAULT_BONJOUR_TIMEOUT is 2000ms = 2s on Windows, 1000ms elsewhere).
        // This was previously AddSeconds(timeout), which turned the 2000ms default into a 2000-SECOND
        // (~33 min) browse on Windows — so the very first WiFi discovery sweep never returned, the 5s
        // poll timer could not tick again, and the detector logged "Starting" then went silent with
        // zero sightings (ScribeHold #1914). Treating the value as the milliseconds it has always been
        // named makes a sweep the intended ~2s.
        TimeSpan window = TimeSpan.FromMilliseconds(timeout);

        using var deadline = new CancellationTokenSource(window);
        int packetsReceived = (await ReceiveUntilAsync(sink, deadline.Token).ConfigureAwait(false)).Packets;

        DropAndClose();

        List<ServiceInstance> services = sink.Resolve();

        // One summary line per browse: packets in, raw record counts, and resolved service instances.
        // This is what turns a silent zero-result sweep into a diagnosable one — we can now tell
        // "no packets arrived" (browser/interface/firewall) from "packets arrived but no PTR/SRV"
        // (wrong service type / parse) from "resolved instances but no addresses" (A records missed).
        _logger.LogInformation(
            "mDNS browse {ServiceType}: {Packets} packet(s) received, {ParseFailures} parse failure(s), " +
            "{PtrTargets} PTR target(s), {SrvNames} SRV name(s), {Instances} resolved instance(s)",
            serviceType, packetsReceived, sink.ParseFailures, sink.PtrTargetCount, sink.SrvCount, services.Count);

        return services;
    }

    /// <summary>
    /// Drain every datagram that arrives on ANY of the per-interface sockets until <paramref name="token"/>
    /// fires, feeding each parsed record into <paramref name="sink"/>. Returns the number of packets
    /// received. Each socket's receive is kept continuously outstanding and re-armed when it completes; the
    /// arrival interface is the socket's own interface index (exact, not a source-IP heuristic).
    ///
    /// Keeping a continuously-pending receive on every socket (rather than polling Available) is the
    /// ScribeHold #1914 round-7 fix: mDNS responses arrive within a few ms of the query, so a poll-and-sleep
    /// loop routinely missed the response. This shared loop is used by both the one-shot browse and the
    /// persistent browser's continuous receive.
    /// </summary>
    /// <summary>
    /// Outcome of one receive window: total packets, the per-interface receive tally, and the set of
    /// interface indices that HAD a live socket this window (so a dead-join detector can tell "an interface
    /// that should have received got 0" from "no such interface").
    /// </summary>
    internal readonly struct ReceiveWindowResult(
        int packets, Dictionary<int, int> perInterface, HashSet<int> boundInterfaces,
        int foreignPackets, Dictionary<int, int> perInterfaceForeign) {
        /// <summary>All packets received this window (includes our own multicast query self-echoes).</summary>
        public int Packets { get; } = packets;
        public Dictionary<int, int> PerInterface { get; } = perInterface;
        public HashSet<int> BoundInterfaces { get; } = boundInterfaces;
        /// <summary>FOREIGN packets only — from another host (real device responses), self-echoes excluded.
        /// The dead-join detector keys off these so an interface hearing only its own echoes is not counted
        /// as alive (ScribeHold #1924).</summary>
        public int ForeignPackets { get; } = foreignPackets;
        public Dictionary<int, int> PerInterfaceForeign { get; } = perInterfaceForeign;
    }

    /// <summary>Return an address with no IPv6 scope id, so a scoped self-echo source matches our unicast.</summary>
    private static IPAddress Scopeless(IPAddress address) {
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0) {
            return new IPAddress(address.GetAddressBytes());
        }
        return address;
    }

    /// <summary>True if <paramref name="source"/> is one of THIS host's own addresses (a query self-echo).</summary>
    private bool IsSelfEcho(IPAddress source) {
        IPAddress bare = Scopeless(source);
        lock (_socketsLock) {
            return _localAddresses.Contains(bare);
        }
    }

    private async Task<ReceiveWindowResult> ReceiveUntilAsync(IMdnsRecordSink sink, CancellationToken token) {
        int packetsReceived = 0;
        int foreignPackets = 0;
        // Per-interface receive tallies for this window. perInterface = ALL packets; perInterfaceForeign =
        // FOREIGN (non-self-echo) only — the dead-join detector keys off the foreign tally (#1924).
        var perInterface = new Dictionary<int, int>();
        var perInterfaceForeign = new Dictionary<int, int>();
        // Snapshot the sockets under the lock so a concurrent RebindSockets() cannot reallocate the list
        // out from under the index-aligned `pending` array. If a rebind happens DURING this window,
        // SocketsRebound cancels the window (see PersistentMdnsBrowser) and the driver re-enters with the
        // fresh snapshot — so this loop always operates on a single, stable generation of sockets.
        (MdnsInterfaceSocket[] sockets, int generation) = SnapshotSockets();
        var boundInterfaces = new HashSet<int>();
        foreach (MdnsInterfaceSocket s in sockets) {
            if (s.InterfaceIndex >= 0) {
                boundInterfaces.Add(s.InterfaceIndex);
            }
        }
        if (sockets.Length == 0) {
            return new ReceiveWindowResult(0, perInterface, boundInterfaces, 0, perInterfaceForeign);
        }

        // One pending receive per socket; index-aligned with `sockets` so a completed task maps back to the
        // socket (hence the arrival interface) it came from.
        var pending = new Task<UdpReceiveResult>?[sockets.Length];
        try {
            while (!token.IsCancellationRequested) {
                for (int i = 0; i < sockets.Length; i++) {
                    pending[i] ??= sockets[i].ReceiveAsync(token).AsTask();
                }

                Task<UdpReceiveResult> completed = await Task.WhenAny(GetPending(pending)).ConfigureAwait(false);
                int slot = Array.IndexOf(pending, completed);

                UdpReceiveResult result;
                try {
                    result = await completed.ConfigureAwait(false);
                }
                catch (OperationCanceledException) {
                    break; // window elapsed
                }
                catch (Exception ex) {
                    // Socket-level read error on one interface — log, clear that pending task, keep listening
                    // on the others for the rest of the window.
                    if (slot >= 0) {
                        pending[slot] = null;
                    }
                    _logger.LogDebug(ex, "mDNS receive error on if {Interface}; continuing to listen",
                        slot >= 0 ? sockets[slot].InterfaceIndex : -1);
                    continue;
                }

                int arrivalIndex = slot >= 0 ? sockets[slot].InterfaceIndex : -1;
                // Re-arm the socket whose receive just completed; leave the others pending.
                if (slot >= 0) {
                    pending[slot] = null;
                }

                bool selfEcho = result.RemoteEndPoint.Address is { } src && IsSelfEcho(src);
                if (arrivalIndex >= 0) {
                    perInterface[arrivalIndex] = perInterface.TryGetValue(arrivalIndex, out int c) ? c + 1 : 1;
                    if (!selfEcho) {
                        perInterfaceForeign[arrivalIndex] = perInterfaceForeign.TryGetValue(arrivalIndex, out int fc) ? fc + 1 : 1;
                    }
                    LogFirstPacketOnInterface(arrivalIndex, generation);
                }
                if (!selfEcho) {
                    foreignPackets++;
                }

                byte[] data = result.Buffer;
                packetsReceived++;
                // Debug (not Trace) so the per-packet source is visible at the service's default Debug
                // level. The arrival interface is now the receiving socket's OWN interface index (exact),
                // the decisive datum for ScribeHold #1917: a sweep that resolves a device must show its
                // adverts arriving on the Wi-Fi index, not only the VPN/virtual if 32.
                _logger.LogDebug("mDNS packet #{Index} received: {Bytes} bytes from {Source} (arrived on if {Interface})",
                    packetsReceived, data.Length, result.RemoteEndPoint,
                    arrivalIndex >= 0 ? arrivalIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) : "?");

                try {
                    ParseMdnsMessage(data, arrivalIndex, sink);
                }
                catch (Exception ex) {
                    // A single malformed packet must not abort the browse, but it was previously swallowed
                    // silently — count and log it so a parse-side failure is distinguishable from "no packets".
                    sink.RecordParseFailure();
                    _logger.LogDebug(ex, "mDNS packet #{Index} from {Source} failed to parse", packetsReceived, result.RemoteEndPoint);
                }
            }
        }
        finally {
            // Observe any still-pending receives' cancellation so they don't surface as unobserved task
            // exceptions when the sockets close.
            foreach (Task<UdpReceiveResult>? p in pending) {
                await ObserveCancelled(p).ConfigureAwait(false);
            }
        }
        return new ReceiveWindowResult(packetsReceived, perInterface, boundInterfaces, foreignPackets, perInterfaceForeign);
    }

    /// <summary>
    /// Log the FIRST packet seen on an interface for the current socket generation, so a join that came up
    /// dead-on-arrival (no packets ever) is distinguishable in the field log from one that simply healed
    /// after a rebind. Fires once per (interface, generation).
    /// </summary>
    private void LogFirstPacketOnInterface(int interfaceIndex, int generation) {
        string key = generation + ":" + interfaceIndex;
        bool firstForKey;
        lock (_socketsLock) {
            firstForKey = _firstPacketLogged.Add(key);
        }
        if (firstForKey) {
            _logger.LogInformation("first mDNS packet received on if {Interface} (socket generation {Gen})",
                interfaceIndex, generation);
        }
    }

    /// <summary>The non-null pending receive tasks, for Task.WhenAny.</summary>
    private static IEnumerable<Task<UdpReceiveResult>> GetPending(Task<UdpReceiveResult>?[] pending) {
        foreach (Task<UdpReceiveResult>? p in pending) {
            if (p != null) {
                yield return p;
            }
        }
    }

    /// <summary>
    /// Awaits a possibly-null pending receive task, swallowing the cancellation/socket-closed exception
    /// it throws when the browse window ends. Prevents an unobserved-task exception when the sockets close.
    /// </summary>
    private static async Task ObserveCancelled(Task<UdpReceiveResult>? pending) {
        if (pending is null) {
            return;
        }
        try {
            await pending.ConfigureAwait(false);
        }
        catch {
            // Expected: the receive was cancelled by the deadline or the socket was closed.
        }
    }

    public async Task SendQuery(byte[] query) {
        // Send the query out of EVERY per-interface socket. Each socket already has its IP_MULTICAST_IF /
        // IPV6_MULTICAST_IF pinned to its own interface at bind time, so the query egresses exactly that
        // interface — mirroring the per-interface receive and what `dns-sd` does. The previous code set the
        // egress option per send on a shared socket; pinning it once per socket is equivalent and removes
        // the cross-send option churn. The iOS device only answers (over IPv4, with a routable A record)
        // when the query actually egresses the Wi-Fi NIC (ScribeHold #1914/#1917).
        // Iterate a snapshot so a concurrent RebindSockets() cannot mutate the list mid-send.
        (MdnsInterfaceSocket[] sockets, _) = SnapshotSockets();
        foreach (MdnsInterfaceSocket sock in sockets) {
            try {
                await sock.SendQueryAsync(query).ConfigureAwait(false);
            }
            catch (Exception ex) {
                // Interface may have gone down between bind and send — skip onto the next one.
                _logger.LogTrace(ex, "mDNS query send skipped on if {Interface}", sock.InterfaceIndex);
            }
        }
    }

    // --- Persistent-mode surface ---------------------------------------------------------------------
    //
    // PersistentMdnsBrowser drives the same sockets continuously rather than open-browse-close per sweep.
    // These thin members let it reuse the bind/send/receive/parse engine without duplicating it, while
    // BrowseService keeps the one-shot lifecycle for the non-polled callers.

    internal Task<ReceiveWindowResult> ReceiveIntoAsync(IMdnsRecordSink sink, CancellationToken token)
        => ReceiveUntilAsync(sink, token);

    internal void DropAndClose() {
        lock (_socketsLock) {
            foreach (MdnsInterfaceSocket sock in _sockets) {
                sock.Dispose();
            }
            _sockets = [];
        }
    }

    public void Dispose() => DropAndClose();

    /// <summary>
    /// Per-sweep record accumulator for the one-shot <see cref="BrowseService"/> path. Resolution requires
    /// PTR + matching SRV in the same window (the historical single-sweep semantics, preserved for the
    /// RemoteD/Tunneld callers that browse once rather than polling).
    /// </summary>
    private sealed class SweepRecordSink : IMdnsRecordSink {
        private readonly HashSet<string> _ptrTargets = [];
        private readonly Dictionary<string, List<Service>> _srvMap = [];
        private readonly Dictionary<string, Dictionary<string, string>> _txtMap = [];
        private readonly Dictionary<string, List<Address>> _hostAddrs = [];

        public int ParseFailures { get; private set; }
        public int PtrTargetCount => _ptrTargets.Count;
        public int SrvCount => _srvMap.Count;

        public void AddPtr(string serviceType, string instance, uint ttl) => _ptrTargets.Add(instance);

        public void AddSrv(string instance, Service service, uint ttl) {
            if (!_srvMap.TryGetValue(instance, out List<Service>? list)) {
                list = [];
                _srvMap[instance] = list;
            }
            list.Add(service);
        }

        public void AddTxt(string instance, Dictionary<string, string> properties, uint ttl)
            => _txtMap[instance] = properties;

        public void AddAddress(string host, Address address, uint ttl) {
            if (!_hostAddrs.TryGetValue(host, out List<Address>? list)) {
                list = [];
                _hostAddrs[host] = list;
            }
            if (!list.Exists(a => a.Ip == address.Ip)) {
                list.Add(address);
            }
        }

        public void RecordParseFailure() => ParseFailures++;

        public List<ServiceInstance> Resolve() {
            List<ServiceInstance> services = [];
            foreach (string inst in _ptrTargets) {
                if (!_srvMap.TryGetValue(inst, out List<Service>? srvs)) {
                    continue;
                }
                foreach (Service srv in srvs) {
                    services.Add(new ServiceInstance(inst) {
                        Host = srv.Target.TrimEnd('.'),
                        Port = srv.Port,
                        Addresses = _hostAddrs.TryGetValue(srv.Target, out List<Address>? addrs) ? addrs : [],
                        Properties = _txtMap.TryGetValue(inst, out Dictionary<string, string>? props) ? props : []
                    });
                }
            }
            return services;
        }
    }
}
