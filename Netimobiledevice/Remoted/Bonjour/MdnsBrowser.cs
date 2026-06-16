using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
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
            if (string.IsNullOrEmpty(iface)) {
                // No local interface is on the same subnet (IPv4) / link (IPv6) as this address, so we
                // cannot reach it. Record under an empty interface anyway for IPv4 (globally routable),
                // but drop unscoped IPv6 link-local — it is unusable without a zone index.
                if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal) {
                    _logger.LogDebug("mDNS A/AAAA {Ip} for {Name} dropped: no local interface on its link", ip, name);
                    return offset;
                }
            }

            if (!hostAddrs.ContainsKey(name)) {
                hostAddrs[name] = [];
            }
            List<Address> existing = hostAddrs[name];
            if (!existing.Exists(a => a.Ip == ip.ToString())) {
                existing.Add(new Address(ip.ToString(), iface));
            }
        }

        return offset;
    }

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
                else {
                    if (ip.IsIPv6LinkLocal) {
                        return ni.Name;
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
        DateTime endTime = DateTime.UtcNow.AddMilliseconds(timeout);
        while (DateTime.UtcNow < endTime) {
            List<Task<UdpReceiveResult>> tasks = [];
            if (_clientV4.Available > 0) {
                tasks.Add(_clientV4.ReceiveAsync());
            }
            if (_clientV6.Available > 0) {
                tasks.Add(_clientV6.ReceiveAsync());
            }
            if (tasks.Count == 0) {
                await Task.Delay(50);
                continue;
            }

            Task<UdpReceiveResult> completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            UdpReceiveResult result = completed.Result;
            byte[] data = result.Buffer;
            packetsReceived++;
            _logger.LogTrace("mDNS packet #{Index} received: {Bytes} bytes from {Source}",
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

    public async Task SendQuery(byte[] query) {
        await _clientV4.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Parse(MdnsMulticastV4), MdnsPort));
        for (int i = 0; i < _interfaces.Length; i++) {
            try {
                await _clientV6.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Parse(MdnsMulticastV6), MdnsPort));
            }
            catch {
                // Catch any errors that might occurs and skip onto the next one
                continue;
            }
        }
    }
}
