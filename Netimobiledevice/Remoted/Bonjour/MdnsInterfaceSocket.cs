using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// One mDNS multicast socket bound to and joined on EXACTLY ONE network interface. This is the
/// per-interface receive primitive that fixes ScribeHold #1917.
///
/// <para>
/// Earlier rounds (#1914) used a single <c>IPAddress.Any:5353</c> socket and joined the mDNS group on
/// every interface as separate memberships. That makes RECEIVE delivery depend on the Windows
/// multicast-binding order: on a host with a low-metric VPN/virtual adapter (Tailscale 100.124.x — the
/// owner's "if 32"), the stack delivers the group's datagrams to the ANY socket via the winning
/// interface only, so the physical Wi-Fi NIC's inbound adverts are dropped and every sweep saw "0
/// advertisements" while <c>dns-sd</c> (which opens a socket per interface) saw the device fine.
/// </para>
///
/// <para>
/// Binding one socket per interface — IPv4 to the interface's own unicast address, IPv6 to
/// <c>IPv6Any</c> + the interface index — makes each socket receive ONLY the datagrams arriving on its
/// interface, independent of any other adapter's metric. The arrival interface is then known exactly
/// (it is THIS socket's interface), with no source-IP/subnet heuristic. Mirrors what <c>dns-sd</c> and
/// well-behaved mDNS responders do.
/// </para>
/// </summary>
internal sealed class MdnsInterfaceSocket : IDisposable {
    private const int MdnsPort = 5353;

    private readonly UdpClient _client;
    private readonly IPEndPoint _multicastTarget;

    private MdnsInterfaceSocket(UdpClient client, NetworkInterface? ni, int interfaceIndex, IPAddress? localAddress,
        AddressFamily family, IPEndPoint multicastTarget) {
        _client = client;
        Interface = ni;
        InterfaceIndex = interfaceIndex;
        LocalAddress = localAddress;
        Family = family;
        _multicastTarget = multicastTarget;
    }

    /// <summary>The interface this socket is bound to and joined on; null for the default-interface fallback.</summary>
    public NetworkInterface? Interface { get; }

    /// <summary>The real OS interface index this socket receives on — the authoritative arrival index.</summary>
    public int InterfaceIndex { get; }

    /// <summary>The local unicast address bound (IPv4 only); null for IPv6 (bound to IPv6Any + index).</summary>
    public IPAddress? LocalAddress { get; }

    public AddressFamily Family { get; }

    /// <summary>
    /// Try to build an IPv4 receive socket bound to <paramref name="localAddress"/> and joined to the mDNS
    /// group on that interface. Returns null (logging at Trace) if the interface cannot be joined.
    /// </summary>
    public static MdnsInterfaceSocket? TryCreateV4(NetworkInterface ni, IPAddress localAddress, IPAddress group,
        ILogger logger) {
        UdpClient? client = null;
        try {
            client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            // Bind to THIS INTERFACE'S UNICAST ADDRESS:5353, NOT IPAddress.Any. With multiple per-interface
            // sockets all wildcard-bound to Any:5353 (+SO_REUSEADDR), Windows delivers each inbound multicast
            // datagram to only ONE of them — the lowest-metric interface, which on this host is the NordLynx
            // VPN — so the Wi-Fi socket joined the group but received ~0 datagrams while dns-sd (one socket
            // per interface, unicast-bound) saw the device fine. Binding to the interface unicast address
            // routes that interface's multicast traffic to THIS socket (measured real-device, VPN on:
            // ~3-4 pkts/window on Wi-Fi with Any-bind -> ~22-24 with unicast-bind). AddMembership +
            // MulticastInterface below still scope join/egress to this interface.
            client.Client.Bind(new IPEndPoint(localAddress, MdnsPort));
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                new MulticastOption(group, localAddress));
            // Egress for queries sent from this socket goes out THIS interface (network-order address).
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
                localAddress.GetAddressBytes());

            int index = ResolveV4Index(ni);
            logger.LogDebug("mDNS IPv4 per-interface socket bound on {Interface} ({LocalIp}, if {Index})",
                ni.Name, localAddress, index);
            return new MdnsInterfaceSocket(client, ni, index, localAddress, AddressFamily.InterNetwork,
                new IPEndPoint(group, MdnsPort));
        }
        catch (Exception ex) {
            logger.LogTrace(ex, "mDNS IPv4 per-interface socket skipped on {Interface} ({LocalIp})", ni.Name, localAddress);
            client?.Dispose();
            return null;
        }
    }

    /// <summary>
    /// Try to build an IPv6 receive socket bound to IPv6Any and joined to the mDNS group on
    /// <paramref name="interfaceIndex"/> (the real OS index). Returns null if the interface cannot be joined.
    /// </summary>
    public static MdnsInterfaceSocket? TryCreateV6(NetworkInterface ni, int interfaceIndex, IPAddress group,
        ILogger logger) {
        UdpClient? client = null;
        try {
            client = new UdpClient(AddressFamily.InterNetworkV6);
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, MdnsPort));
            client.JoinMulticastGroup(interfaceIndex, group);
            // Egress for queries sent from this socket goes out THIS interface index (host order).
            client.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, interfaceIndex);

            logger.LogDebug("mDNS IPv6 per-interface socket bound on {Interface} (if {Index})", ni.Name, interfaceIndex);
            return new MdnsInterfaceSocket(client, ni, interfaceIndex, null, AddressFamily.InterNetworkV6,
                new IPEndPoint(group, MdnsPort));
        }
        catch (Exception ex) {
            logger.LogTrace(ex, "mDNS IPv6 per-interface socket skipped on {Interface} (if {Index})", ni.Name, interfaceIndex);
            client?.Dispose();
            return null;
        }
    }

    /// <summary>
    /// Fallback: an IPv4 socket joined on the OS default multicast interface (single-arg join), used only
    /// when no per-interface socket could be bound. Preserves the degenerate single-NIC behaviour rather
    /// than leaving the browser with no socket at all. The arrival interface index is unknown (-1).
    /// </summary>
    public static MdnsInterfaceSocket? TryCreateV4Default(IPAddress group, ILogger logger) {
        UdpClient? client = null;
        try {
            client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
            client.JoinMulticastGroup(group);
            logger.LogDebug("mDNS IPv4 default-interface socket bound");
            return new MdnsInterfaceSocket(client, ni: null, interfaceIndex: -1, localAddress: null,
                AddressFamily.InterNetwork, new IPEndPoint(group, MdnsPort));
        }
        catch (Exception ex) {
            logger.LogWarning(ex, "mDNS IPv4 default-interface socket bind failed");
            client?.Dispose();
            return null;
        }
    }

    private static int ResolveV4Index(NetworkInterface ni) {
        try {
            return ni.GetIPProperties().GetIPv4Properties().Index;
        }
        catch {
            return -1;
        }
    }

    /// <summary>Receive one datagram on this interface's socket.</summary>
    public ValueTask<UdpReceiveResult> ReceiveAsync(CancellationToken token) => _client.ReceiveAsync(token);

    /// <summary>Send <paramref name="query"/> to the mDNS multicast group out of this interface.</summary>
    public Task SendQueryAsync(byte[] query) => _client.SendAsync(query, query.Length, _multicastTarget);

    public void Dispose() {
        try {
            _client.Close();
        }
        catch {
            // Socket already closing.
        }
    }
}
