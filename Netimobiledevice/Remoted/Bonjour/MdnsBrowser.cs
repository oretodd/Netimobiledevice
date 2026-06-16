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

internal class MdnsBrowser {
    private const string MdnsMulticastV4 = "224.0.0.251";
    private const string MdnsMulticastV6 = "ff02::fb";
    private const int MdnsPort = 5353;

    private readonly UdpClient _clientV4;
    private readonly UdpClient _clientV6;
    private readonly NetworkInterface[] _interfaces;
    private readonly ILogger _logger;

    public MdnsBrowser(ILogger? logger = null) {
        _logger = logger ?? NullLogger.Instance;
        _interfaces = [.. NetworkInterface.GetAllNetworkInterfaces()];
        _clientV4 = BindUdpV4();
        _clientV6 = BindUdpV6();
    }

    private UdpClient BindUdpV4() {
        UdpClient client = new UdpClient(AddressFamily.InterNetwork);
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));

        // Join the mDNS multicast group on EVERY IPv4-capable interface, not just the system default.
        // The single-argument JoinMulticastGroup overload joins only on the default multicast interface,
        // so on a multi-NIC machine an iOS device advertising on a non-default adapter is never received
        // (the silent zero-result sweep of ScribeHold #1914). Mirror the per-interface loop the IPv6
        // path already uses. A device only needs to be reachable on ONE interface, so a failed join on
        // an interface that has no IPv4 / is down is logged at Trace and skipped, not fatal.
        IPAddress multicastV4 = IPAddress.Parse(MdnsMulticastV4);
        int joined = 0;
        foreach (NetworkInterface ni in _interfaces) {
            if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast) {
                continue;
            }

            foreach (UnicastIPAddressInformation uni in ni.GetIPProperties().UnicastAddresses) {
                if (uni.Address.AddressFamily != AddressFamily.InterNetwork) {
                    continue;
                }

                try {
                    client.Client.SetSocketOption(
                        SocketOptionLevel.IP,
                        SocketOptionName.AddMembership,
                        new MulticastOption(multicastV4, uni.Address));
                    joined++;
                    _logger.LogDebug("mDNS IPv4 multicast join OK on {Interface} ({LocalIp})", ni.Name, uni.Address);
                }
                catch (Exception ex) {
                    _logger.LogTrace(ex, "mDNS IPv4 multicast join skipped on {Interface} ({LocalIp})", ni.Name, uni.Address);
                }
            }
        }

        if (joined == 0) {
            // No per-interface join succeeded — fall back to the default-interface join so a
            // single-NIC machine still works, and surface that the per-interface fan-out found nothing.
            _logger.LogWarning("mDNS IPv4 multicast: no per-interface join succeeded; falling back to default interface");
            try {
                client.JoinMulticastGroup(multicastV4);
            }
            catch (Exception ex) {
                _logger.LogWarning(ex, "mDNS IPv4 multicast default-interface join failed");
            }
        }
        else {
            _logger.LogDebug("mDNS IPv4 multicast joined on {Count} interface address(es)", joined);
        }

        return client;
    }

    private UdpClient BindUdpV6() {
        UdpClient client = new UdpClient(AddressFamily.InterNetworkV6);
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, MdnsPort));

        IPAddress multicastV6 = IPAddress.Parse(MdnsMulticastV6);
        int joined = 0;
        for (int i = 0; i < _interfaces.Length; i++) {
            try {
                client.JoinMulticastGroup(i, multicastV6);
                joined++;
            }
            catch (Exception ex) {
                // Interface may have no IPv6 / be down — skip onto the next one.
                _logger.LogTrace(ex, "mDNS IPv6 multicast join skipped on interface index {Index}", i);
                continue;
            }
        }

        _logger.LogDebug("mDNS IPv6 multicast joined on {Count} interface index(es)", joined);
        return client;
    }

    private void ParseMdnsMessage(
        byte[] data,
        HashSet<string> ptrTargets,
        Dictionary<string, List<Service>> srvMap,
        Dictionary<string, Dictionary<string, string>> txtMap,
        Dictionary<string, List<Address>> hostAddrs
    ) {
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

        for (int i = 0; i < anCount + nsCount + arCount; i++) {
            offset = ParseRR(data, offset, ptrTargets, srvMap, txtMap, hostAddrs);
        }
    }

    private int ParseRR(
        byte[] data,
        int offset,
        HashSet<string> ptrTargets,
        Dictionary<string, List<Service>> srvMap,
        Dictionary<string, Dictionary<string, string>> txtMap,
        Dictionary<string, List<Address>> hostAddrs
    ) {
        (string? name, int newOffset) = DnsHelpers.DecodeName(data, offset);
        offset = newOffset;

        if (offset + 10 > data.Length) {
            return offset;
        }
        ushort rtype = (ushort) ((data[offset] << 8) | data[offset + 1]);
        ushort rclass = (ushort) ((data[offset + 2] << 8) | data[offset + 3]);
        ushort rdlen = (ushort) ((data[offset + 8] << 8) | data[offset + 9]);
        offset += 10;

        if (offset + rdlen > data.Length) {
            return offset;
        }
        byte[] rdata = new byte[rdlen];
        Array.Copy(data, offset, rdata, 0, rdlen);
        offset += rdlen;

        if (rtype == DnsHelpers.QTYPE_PTR) {
            (string? target, int _) = DnsHelpers.DecodeName(rdata, 0);
            ptrTargets.Add(target);
        }
        else if (rtype == DnsHelpers.QTYPE_SRV && rdlen >= 6) {
            ushort port = (ushort) ((rdata[4] << 8) | rdata[5]);
            (string? target, int _) = DnsHelpers.DecodeName(rdata, 6);
            if (!srvMap.ContainsKey(name)) {
                srvMap[name] = [];
            }
            srvMap[name].Add(new(target, port));
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
            txtMap[name] = dict;
        }
        else if ((rtype == DnsHelpers.QTYPE_A && rdlen == 4) ||
                 (rtype == DnsHelpers.QTYPE_AAAA && rdlen == 16)) {
            IPAddress ip = new IPAddress(rdata);
            string iface = PickInterfaceForIp(ip);

            // ALWAYS record the address — including IPv6 link-local (fe80::). Real iOS devices advertise
            // mobdev2 with ONLY an IPv6 link-local AAAA record (verified via dns-sd, #1914), so dropping
            // link-local would resolve every such device to zero connectable addresses. The zone index is
            // carried by Address.FullIp ("fe80::...%iface"); PickInterfaceForIp supplies the matching
            // local interface so the scope is correct. An empty iface is still recorded (best effort)
            // rather than discarded — discarding here is exactly what broke WiFi discovery.
            if (!hostAddrs.ContainsKey(name)) {
                hostAddrs[name] = [];
            }
            List<Address> existing = hostAddrs[name];
            if (!existing.Exists(a => a.Ip == ip.ToString())) {
                existing.Add(new Address(ip.ToString(), iface));
                _logger.LogDebug("mDNS {Type} {Ip} for {Name} on interface '{Interface}'",
                    ip.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A", ip, name, iface);
            }
        }

        return offset;
    }

    /// <summary>
    /// Finds the local interface that can reach <paramref name="ip"/> and returns the zone token to use
    /// in a scoped address. For IPv6 this is the interface INDEX (the zone Windows requires in
    /// "fe80::...%index"); for IPv4 it is the interface name (informational — IPv4 has no zone).
    /// Returns empty if no local interface matches.
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
    /// Discover a DNS-SD/mDNS service type (e.g. "_remoted._tcp.local.") on the local network.
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

        HashSet<string> ptrTargets = [];
        Dictionary<string, List<Service>> srvMap = [];
        Dictionary<string, Dictionary<string, string>> txtMap = [];
        Dictionary<string, List<Address>> hostAddrs = [];
        int packetsReceived = 0;
        int parseFailures = 0;

        // timeout is MILLISECONDS (DEFAULT_BONJOUR_TIMEOUT is 2000ms = 2s on Windows, 1000ms elsewhere).
        // This was previously AddSeconds(timeout), which turned the 2000ms default into a 2000-SECOND
        // (~33 min) browse on Windows — so the very first WiFi discovery sweep never returned, the 5s
        // poll timer could not tick again, and the detector logged "Starting" then went silent with
        // zero sightings (ScribeHold #1914). Treating the value as the milliseconds it has always been
        // named makes a sweep the intended ~2s.
        TimeSpan window = TimeSpan.FromMilliseconds(timeout);

        // Continuously-pending receive on each socket, awaited against a single overall deadline.
        //
        // The previous loop only issued ReceiveAsync() when UdpClient.Available > 0 at poll time and
        // otherwise slept 50ms. mDNS responses arrive within a few ms of the query, so the response
        // routinely landed during a sleep and only ONE buffered datagram was drained per 50ms tick —
        // on a real device this surfaced as "1 packet received, 0 PTR" while `dns-sd` (which keeps a
        // receive outstanding) saw the advert fine (ScribeHold #1914). Keeping a pending ReceiveAsync
        // on each socket means every datagram is taken the instant it arrives, for the whole window.
        using var deadline = new CancellationTokenSource(window);
        Task<UdpReceiveResult>? recvV4 = null;
        Task<UdpReceiveResult>? recvV6 = null;
        try {
            while (!deadline.IsCancellationRequested) {
                recvV4 ??= _clientV4.ReceiveAsync(deadline.Token).AsTask();
                recvV6 ??= _clientV6.ReceiveAsync(deadline.Token).AsTask();

                Task<UdpReceiveResult> completed = await Task.WhenAny(recvV4, recvV6).ConfigureAwait(false);

                UdpReceiveResult result;
                try {
                    result = await completed.ConfigureAwait(false);
                }
                catch (OperationCanceledException) {
                    break; // window elapsed
                }
                catch (Exception ex) {
                    // Socket-level read error on one stack — log, clear that pending task, keep listening
                    // on the other for the rest of the window.
                    if (completed == recvV4) { recvV4 = null; } else { recvV6 = null; }
                    _logger.LogDebug(ex, "mDNS receive error; continuing to listen");
                    continue;
                }

                // Re-arm the socket whose receive just completed; leave the other pending.
                if (completed == recvV4) { recvV4 = null; } else { recvV6 = null; }

                byte[] data = result.Buffer;
                packetsReceived++;
                // Debug (not Trace) so the per-packet source is visible at the service's default Debug
                // level: a sweep reporting "0 advertisements" is otherwise indistinguishable between
                // "the only packets came from unrelated mDNS responders" and "our target's advert
                // arrived but was not parsed". The source IP tells which device/subnet answered (#1914).
                _logger.LogDebug("mDNS packet #{Index} received: {Bytes} bytes from {Source}",
                    packetsReceived, data.Length, result.RemoteEndPoint);

                try {
                    ParseMdnsMessage(data, ptrTargets, srvMap, txtMap, hostAddrs);
                }
                catch (Exception ex) {
                    // A single malformed packet must not abort the browse, but it was previously swallowed
                    // silently — count and log it so a parse-side failure is distinguishable from "no packets".
                    parseFailures++;
                    _logger.LogDebug(ex, "mDNS packet #{Index} from {Source} failed to parse", packetsReceived, result.RemoteEndPoint);
                }
            }
        }
        finally {
            // Observe any still-pending receive's cancellation so it doesn't surface as an unobserved
            // task exception when the sockets close below.
            await ObserveCancelled(recvV4).ConfigureAwait(false);
            await ObserveCancelled(recvV6).ConfigureAwait(false);
        }

        // Single-arg DropMulticastGroup does not symmetrically drop the per-interface IPv4 memberships
        // added above, but that is not a leak: both sockets are Close()d immediately, so the OS reclaims
        // every membership with the socket. The Drop calls are kept as a best-effort tidy-up.
        _clientV4.DropMulticastGroup(IPAddress.Parse(MdnsMulticastV4));
        _clientV6.DropMulticastGroup(IPAddress.Parse(MdnsMulticastV6));
        _clientV4.Close();
        _clientV6.Close();

        List<ServiceInstance> services = [];
        foreach (string inst in ptrTargets) {
            if (!srvMap.ContainsKey(inst)) {
                continue;
            }
            foreach (Service srv in srvMap[inst]) {
                ServiceInstance si = new(inst) {
                    Host = srv.Target.TrimEnd('.'),
                    Port = srv.Port,
                    Addresses = hostAddrs.TryGetValue(srv.Target, out List<Address>? value1) ? value1 : [],
                    Properties = txtMap.TryGetValue(inst, out Dictionary<string, string>? value) ? value : []
                };
                services.Add(si);
            }
        }

        // One summary line per browse: packets in, raw record counts, and resolved service instances.
        // This is what turns a silent zero-result sweep into a diagnosable one — we can now tell
        // "no packets arrived" (browser/interface/firewall) from "packets arrived but no PTR/SRV"
        // (wrong service type / parse) from "resolved instances but no addresses" (A records missed).
        _logger.LogInformation(
            "mDNS browse {ServiceType}: {Packets} packet(s) received, {ParseFailures} parse failure(s), " +
            "{PtrTargets} PTR target(s), {SrvNames} SRV name(s), {Instances} resolved instance(s)",
            serviceType, packetsReceived, parseFailures, ptrTargets.Count, srvMap.Count, services.Count);

        return services;
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
        var v4Target = new IPEndPoint(IPAddress.Parse(MdnsMulticastV4), MdnsPort);
        await _clientV4.SendAsync(query, query.Length, v4Target).ConfigureAwait(false);

        // Send the IPv6 query once PER interface index, setting the multicast egress interface each time.
        // The previous loop sent N copies but never varied the outgoing interface (MulticastInterface
        // socket option), so every copy left via the default interface and the query never reached a
        // device whose link-local advert lives on a non-default NIC (e.g. Wi-Fi). iOS devices advertise
        // mobdev2 on IPv6 link-local, so reaching the right interface is what makes them discoverable.
        var v6Target = new IPEndPoint(IPAddress.Parse(MdnsMulticastV6), MdnsPort);
        for (int i = 0; i < _interfaces.Length; i++) {
            try {
                // IPv6 MulticastInterface takes the interface INDEX in host order (unlike the IPv4
                // option, which takes a network-order address). i is the index we joined the group on.
                _clientV6.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, i);
                await _clientV6.SendAsync(query, query.Length, v6Target).ConfigureAwait(false);
            }
            catch {
                // Interface may have no IPv6 / be down — skip onto the next one.
                continue;
            }
        }
    }
}
