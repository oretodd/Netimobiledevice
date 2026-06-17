using Microsoft.Extensions.Logging;
using Netimobiledevice.Remoted.Bonjour;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetimobiledeviceTest.Remoted.Bonjour;

/// <summary>
/// Regression guard for ScribeHold #1914 QA round 5: the mDNS browser joined / sent on the IPv6
/// multicast group using the 0..N-1 ARRAY POSITION of each interface in
/// <see cref="NetworkInterface.GetAllNetworkInterfaces"/>, not the interface's real OS index. On a
/// host whose Wi-Fi adapter has a sparse index (e.g. 26 — the common case; OS indexes look like
/// 1,5,10,19,26,32,38,62) the multicast group was NEVER joined on the Wi-Fi NIC, so the
/// <c>_apple-mobdev2._tcp</c> adverts (which Apple devices send on IPv6 link-local on exactly that
/// NIC) were never received and discovery resolved zero devices — while <c>dns-sd</c> on the same
/// machine found them on if 26.
/// <para>
/// The fix joins/sends on the real OS index from
/// <c>NetworkInterface.GetIPProperties().GetIPv6Properties().Index</c>, and logs the actual joined
/// index list so a real-device log can confirm the Wi-Fi index is among them.
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
    /// are what a correct join must use. On a multi-NIC box these are sparse and frequently exceed the
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

    private static List<int> ParseJoinedIndexes(IEnumerable<string> messages)
    {
        const string prefix = "mDNS IPv6 multicast joined on interface index(es): [";
        foreach (string m in messages) {
            int start = m.IndexOf(prefix, StringComparison.Ordinal);
            if (start < 0) {
                continue;
            }
            int open = m.IndexOf('[', start);
            int close = m.IndexOf(']', open);
            string inner = m.Substring(open + 1, close - open - 1).Trim();
            if (inner.Length == 0) {
                return [];
            }
            return [.. inner.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(int.Parse)];
        }
        Assert.Fail("No 'mDNS IPv6 multicast joined on interface index(es)' summary line was emitted. Messages: "
            + string.Join(" | ", messages));
        return [];
    }

    [TestMethod]
    public void Ctor_LogsJoinedIpv6InterfaceIndexes_AsRealOsIndexes_NotArrayPositions()
    {
        CapturingLogger logger = new();

        // Constructing the browser performs the multicast joins and logs the joined index list.
        _ = new MdnsBrowser(logger);

        HashSet<int> realIndexes = RealIpv6Indexes();
        if (realIndexes.Count == 0) {
            Assert.Inconclusive("Host has no up, multicast-capable IPv6 interface — nothing to assert.");
            return;
        }

        List<int> joined = ParseJoinedIndexes(logger.Messages);
        Assert.IsTrue(joined.Count > 0, "Expected at least one joined IPv6 interface index on a host with IPv6 NICs.");

        // Every joined index must be a REAL OS interface index. Array-position indexing (0..N-1) would
        // produce values that are not in the real-index set whenever the host has any sparse index — the
        // exact #1914 failure. This is the load-bearing assertion.
        foreach (int idx in joined) {
            Assert.IsTrue(realIndexes.Contains(idx),
                $"Joined index {idx} is not a real OS IPv6 interface index ({string.Join(",", realIndexes)}). "
                + "This is the #1914 array-position-vs-OS-index bug.");
        }
    }

    [TestMethod]
    public void Ctor_DoesNotEmitDenseZeroBasedIndexSequence_WhenHostHasSparseIndexes()
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
        _ = new MdnsBrowser(logger);
        List<int> joined = ParseJoinedIndexes(logger.Messages);

        List<int> denseSequence = [.. Enumerable.Range(0, joined.Count)];
        CollectionAssert.AreNotEqual(denseSequence, joined,
            "Joined indexes form the dense 0..N-1 sequence — the old array-position bug has regressed.");
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
}
