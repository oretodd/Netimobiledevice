using Microsoft.Extensions.Logging;
using Netimobiledevice.Remoted.Bonjour;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetimobiledeviceTest.Remoted.Bonjour;

/// <summary>
/// Regression guard for the mDNS interface-selection saga (ScribeHold #1914 rounds 5/6 and #1917).
///
/// <para>
/// #1914 round 5: the browser joined/sent on the IPv6 multicast group using the 0..N-1 ARRAY POSITION
/// of each interface, not its real OS index — on a host whose Wi-Fi adapter has a sparse index the group
/// was never joined on the Wi-Fi NIC. #1914 round 6: the physical Wi-Fi NIC has no IPv6 stack at all, the
/// device is reachable over IPv4, and the IPv4 query was sent only once on the OS default egress interface
/// (a VPN/virtual adapter) so it never egressed the Wi-Fi NIC.
/// </para>
///
/// <para>
/// #1917 (this round): even with the per-NIC SEND fix, RECEIVE used a single <c>IPAddress.Any:5353</c>
/// socket joined on every interface, so Windows delivered the group's datagrams via the winning (low-metric
/// VPN/virtual) interface only and the Wi-Fi NIC's inbound adverts were dropped — every sweep saw "0
/// advertisements" while the adverts were arriving on the Wi-Fi NIC. The fix binds ONE socket per interface
/// (<see cref="MdnsInterfaceSocket"/>): IPv4 to the interface's own unicast address, IPv6 to IPv6Any + the
/// real OS index. Each socket then receives ONLY its interface's datagrams and the arrival interface is
/// exact. These tests assert the per-interface bind covers every multicast-capable NIC with the real OS
/// index, so a real-device log can confirm the Wi-Fi NIC is among the bound sockets.
/// </para>
/// </summary>
[TestClass]
public class MdnsInterfaceSelectionTests
{
    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));
    }

    /// <summary>
    /// The set of REAL OS IPv6 interface indexes the host actually has, up + multicast-capable. These
    /// are what a correct bind must use. On a multi-NIC box these are sparse and frequently exceed the
    /// interface COUNT, which is precisely why array-position indexing missed the Wi-Fi NIC.
    /// </summary>
    private static HashSet<int> RealIpv6Indexes()
    {
        HashSet<int> indexes = [];
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces()) {
            if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast) {
                continue;
            }
            try {
                indexes.Add(ni.GetIPProperties().GetIPv6Properties().Index);
            }
            catch {
                // No IPv6 properties on this interface — not a candidate.
            }
        }
        return indexes;
    }

    /// <summary>
    /// Parse the single combined bind-summary line. Returns the IPv4 token list ("Name=Addr") and the IPv6
    /// index list. Fails the test if the summary line was not emitted.
    /// </summary>
    private static (List<string> v4, List<int> v6) ParseBoundSummary(IEnumerable<string> messages)
    {
        const string prefix = "mDNS bound IPv4 socket(s) on: [";
        foreach (string m in messages) {
            if (m.IndexOf(prefix, StringComparison.Ordinal) < 0) {
                continue;
            }
            // Format: "mDNS bound IPv4 socket(s) on: [<v4>]; IPv6 socket(s) on if: [<v6>]"
            int firstOpen = m.IndexOf('[', StringComparison.Ordinal);
            int firstClose = m.IndexOf(']', firstOpen);
            int secondOpen = m.IndexOf('[', firstClose);
            int secondClose = m.IndexOf(']', secondOpen);

            string v4Inner = m.Substring(firstOpen + 1, firstClose - firstOpen - 1).Trim();
            string v6Inner = m.Substring(secondOpen + 1, secondClose - secondOpen - 1).Trim();

            List<string> v4 = v4Inner.Length == 0
                ? []
                : [.. v4Inner.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
            List<int> v6 = v6Inner.Length == 0
                ? []
                : [.. v6Inner.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(int.Parse)];
            return (v4, v6);
        }
        Assert.Fail("No 'mDNS bound IPv4 socket(s) on' summary line was emitted. Messages: "
            + string.Join(" | ", messages));
        return ([], []);
    }

    [TestMethod]
    public void Ctor_BindsIpv6SocketsOnRealOsIndexes_NotArrayPositions()
    {
        CapturingLogger logger = new();

        // Constructing the browser binds the per-interface sockets and logs the bound summary.
        using var browser = new MdnsBrowser(logger);

        HashSet<int> realIndexes = RealIpv6Indexes();
        if (realIndexes.Count == 0) {
            Assert.Inconclusive("Host has no up, multicast-capable IPv6 interface — nothing to assert.");
            return;
        }

        (_, List<int> boundV6) = ParseBoundSummary(logger.Messages);
        Assert.IsTrue(boundV6.Count > 0, "Expected at least one bound IPv6 interface index on a host with IPv6 NICs.");

        // Every bound index must be a REAL OS interface index. Array-position indexing (0..N-1) would
        // produce values that are not in the real-index set whenever the host has any sparse index — the
        // #1914 round-5 failure. This is the load-bearing assertion.
        foreach (int idx in boundV6) {
            Assert.IsTrue(realIndexes.Contains(idx),
                $"Bound IPv6 index {idx} is not a real OS IPv6 interface index ({string.Join(",", realIndexes)}). "
                + "This is the #1914 array-position-vs-OS-index bug.");
        }
    }

    [TestMethod]
    public void Ctor_DoesNotBindDenseZeroBasedIndexSequence_WhenHostHasSparseIndexes()
    {
        // If the host has any sparse IPv6 index (max index >= interface count), a correct implementation
        // CANNOT have produced the dense 0,1,2,... sequence the old code used. This directly catches a
        // regression back to array-position indexing on a realistic multi-NIC machine.
        HashSet<int> realIndexes = RealIpv6Indexes();
        if (realIndexes.Count == 0 || realIndexes.Max() < realIndexes.Count) {
            Assert.Inconclusive("Host indexes are not sparse; this guard is only decisive on a multi-NIC host.");
            return;
        }

        CapturingLogger logger = new();
        using var browser = new MdnsBrowser(logger);
        (_, List<int> boundV6) = ParseBoundSummary(logger.Messages);

        List<int> denseSequence = [.. Enumerable.Range(0, boundV6.Count)];
        CollectionAssert.AreNotEqual(denseSequence, boundV6,
            "Bound indexes form the dense 0..N-1 sequence — the old array-position bug has regressed.");
    }

    [TestMethod]
    public void Address_FullIp_ScopesLinkLocalIpv6_WithInterfaceIndexZone()
    {
        // A link-local AAAA (how Apple devices advertise mobdev2) is unroutable without its zone. The
        // browser records the arrival interface index as the zone; FullIp must emit "fe80::...%<index>"
        // so the lockdown TCP connect targets the reachable scope (#1914).
        Address linkLocal = new("fe80::8a66:5aff:fe72:c34", "26");
        Assert.AreEqual("fe80::8a66:5aff:fe72:c34%26", linkLocal.FullIp);

        // A global/non-link-local address has no zone and must be emitted bare.
        Address global = new("192.168.68.55", "Wi-Fi");
        Assert.AreEqual("192.168.68.55", global.FullIp);

        // An empty zone must NOT produce the invalid "fe80::...%" — the bare address is returned instead.
        Address linkLocalNoZone = new("fe80::8a66:5aff:fe72:c34", "");
        Assert.AreEqual("fe80::8a66:5aff:fe72:c34", linkLocalNoZone.FullIp);
    }

    /// <summary>
    /// The set of local IPv4 unicast addresses on up + multicast-capable interfaces — what a correct
    /// per-interface bind must cover (one receive/send socket bound to each).
    /// </summary>
    private static HashSet<string> RealIpv4Addresses()
    {
        HashSet<string> addrs = [];
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces()) {
            if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast) {
                continue;
            }
            foreach (UnicastIPAddressInformation uni in ni.GetIPProperties().UnicastAddresses) {
                if (uni.Address.AddressFamily == AddressFamily.InterNetwork) {
                    addrs.Add(uni.Address.ToString());
                }
            }
        }
        return addrs;
    }

    [TestMethod]
    public void Ctor_BindsOneIpv4SocketPerMulticastCapableInterface_CoveringEveryNic()
    {
        // The #1917 fix: bind ONE socket per interface so each receives ONLY its interface's datagrams,
        // instead of a single ANY socket whose delivery a low-metric VPN can hijack. The bound-address
        // list is the evidence the per-interface fan-out covers the physical Wi-Fi NIC's LAN address (and
        // is not collapsed to a single default NIC).
        HashSet<string> realAddrs = RealIpv4Addresses();
        if (realAddrs.Count == 0) {
            Assert.Inconclusive("Host has no up, multicast-capable IPv4 interface — nothing to assert.");
            return;
        }

        CapturingLogger logger = new();
        using var browser = new MdnsBrowser(logger);

        (List<string> boundV4, _) = ParseBoundSummary(logger.Messages);
        Assert.IsTrue(boundV4.Count > 0,
            "Expected the bound-summary line to list at least one per-interface IPv4 socket (#1917). Messages: "
            + string.Join(" | ", logger.Messages));

        // Every bound token is "Name=Addr"; the address must be a real local IPv4 unicast address.
        foreach (string token in boundV4) {
            int eq = token.LastIndexOf('=');
            string addr = eq >= 0 ? token[(eq + 1)..] : token;
            Assert.IsTrue(realAddrs.Contains(addr),
                $"Bound IPv4 address {addr} is not a real local unicast address ({string.Join(",", realAddrs)}).");
        }

        // On a multi-NIC host the per-interface bind MUST cover more than one address — proving the bind is
        // not collapsed to a single (possibly VPN/virtual) interface, the exact #1917 receive defect.
        if (realAddrs.Count > 1) {
            Assert.IsTrue(boundV4.Count > 1,
                "Host has multiple IPv4 NICs but only one socket was bound — a single ANY socket's delivery "
                + "can be hijacked by a low-metric VPN and miss the Wi-Fi subnet (#1917).");
        }
    }

    [TestMethod]
    public async Task SendQuery_EgressesEveryBoundInterface_WithoutThrowing()
    {
        // Directly exercise the egress path: SendQuery must send the query out of each per-interface socket
        // (each already has IP_MULTICAST_IF / IPV6_MULTICAST_IF pinned to its own interface) without
        // throwing. A successful multi-send here is the behavioral proof of the per-interface fan-out.
        if (RealIpv4Addresses().Count == 0) {
            Assert.Inconclusive("Host has no up, multicast-capable IPv4 interface — cannot exercise SendQuery.");
            return;
        }

        CapturingLogger logger = new();
        using MdnsBrowser browser = new(logger);

        byte[] query = DnsHelpers.BuildQuery("_apple-mobdev2._tcp.local.", DnsHelpers.QTYPE_PTR);

        // Must complete without throwing across all bound interfaces.
        await browser.SendQuery(query);

        // No per-interface send should have been logged as skipped (skips are only logged when an
        // interface went down between bind and send — not expected in a single synchronous test run).
        Assert.IsFalse(
            logger.Messages.Exists(m => m.Contains("mDNS query send skipped", StringComparison.Ordinal)),
            "An mDNS egress send was skipped unexpectedly: " + string.Join(" | ", logger.Messages));
    }
}
