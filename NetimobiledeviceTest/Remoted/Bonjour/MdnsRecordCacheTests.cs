using Netimobiledevice.Remoted.Bonjour;

namespace NetimobiledeviceTest.Remoted.Bonjour;

/// <summary>
/// Regression guard for ScribeHold #1914 QA round 7: the mDNS browser resolved a service instance only
/// when its PTR + SRV + A records all arrived inside ONE ~1000ms browse window. mDNS responses are
/// asynchronous and often split PTR, SRV, and A across separate packets/sweeps, so a real device's
/// advert (proven by the round-6 instrumentation to be arriving on the Wi-Fi interface) almost never
/// resolved — every sweep started from an empty map. <see cref="MdnsRecordCache"/> accumulates records
/// across sweeps and resolves an instance the moment its PTR, SRV, and at least one address are
/// simultaneously live, regardless of which sweep each arrived in. These tests pin that cross-sweep
/// behaviour and the TTL/goodbye expiry, all on a deterministic injected clock (no real sockets/NICs).
/// </summary>
[TestClass]
public class MdnsRecordCacheTests
{
    private const string Mobdev2 = "_apple-mobdev2._tcp.local.";
    private const string Instance = "aa:bb:cc:dd:ee:ff@toddpad._apple-mobdev2._tcp.local.";
    private const string Host = "toddpad.local.";

    private sealed class FakeClock
    {
        public DateTime UtcNow { get; set; } = new DateTime(2026, 6, 17, 0, 0, 0, DateTimeKind.Utc);
        public void Advance(TimeSpan by) => UtcNow += by;
    }

    [TestMethod]
    public void Resolve_RequiresPtrSrvAndAddress_AllPresent()
    {
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        // PTR alone — not resolvable (no SRV, no address).
        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 60);
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count, "PTR with no SRV/A must not resolve.");

        // PTR + SRV — still not resolvable (no address yet).
        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 60);
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count, "PTR+SRV with no address must not resolve.");

        // PTR + SRV + A — now resolvable.
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 60);
        var resolved = cache.Resolve(Mobdev2);
        Assert.AreEqual(1, resolved.Count, "PTR+SRV+A all present must resolve exactly one instance.");
        Assert.AreEqual(Instance, resolved[0].Instance);
        Assert.AreEqual("toddpad.local", resolved[0].Host);
        Assert.AreEqual((ushort) 32498, resolved[0].Port);
        Assert.AreEqual("192.168.68.82", resolved[0].Addresses[0].FullIp);
    }

    [TestMethod]
    public void Resolve_CombinesRecordsArrivingAcrossSeparateSweeps()
    {
        // The core round-7 scenario: PTR in sweep N, SRV in sweep N+1, A in sweep N+2. The old per-sweep
        // browser would have discarded the PTR before the SRV arrived and never resolved the device.
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 60);          // sweep N
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count);

        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 60);  // sweep N+1
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count);

        cache.AddAddress(Host, new Address("fe80::ccdd:a6ff:feb4:ae24", "26"), ttlSeconds: 60);  // sweep N+2
        clock.Advance(TimeSpan.FromSeconds(2));

        var resolved = cache.Resolve(Mobdev2);
        Assert.AreEqual(1, resolved.Count, "Records that arrived in three separate sweeps must combine into one resolved instance.");
        Assert.AreEqual("fe80::ccdd:a6ff:feb4:ae24%26", resolved[0].Addresses[0].FullIp);
    }

    [TestMethod]
    public void Resolve_OnlyReturnsInstancesOfTheQueriedServiceType()
    {
        // Other Bonjour services on the LAN (AirPlay, companion-link) must NOT be counted as mobdev2
        // devices (round-7 item 3). A PTR under a different service type never appears in the mobdev2
        // resolution, even with a complete SRV+A.
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        const string airplayType = "_airplay._tcp.local.";
        const string airplayInstance = "AppleTV._airplay._tcp.local.";
        cache.AddPtr(airplayType, airplayInstance, ttlSeconds: 60);
        cache.AddSrv(airplayInstance, new Service("appletv.local.", 7000), ttlSeconds: 60);
        cache.AddAddress("appletv.local.", new Address("192.168.68.90", "Wi-Fi"), ttlSeconds: 60);

        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count, "A non-mobdev2 service must not appear in the mobdev2 resolution.");
        Assert.AreEqual(1, cache.Resolve(airplayType).Count, "The AirPlay instance still resolves under its own type.");
    }

    [TestMethod]
    public void Resolve_DropsInstanceAfterTtlExpiry()
    {
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 10);
        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 10);
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 10);
        Assert.AreEqual(1, cache.Resolve(Mobdev2).Count, "Fresh records resolve.");

        // Past the TTL, the records are no longer live and the instance drops out of the resolved set.
        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count, "Records past their TTL must not resolve (device left the LAN).");
    }

    [TestMethod]
    public void Goodbye_TtlZero_EvictsImmediately()
    {
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 120);
        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 120);
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 120);
        Assert.AreEqual(1, cache.Resolve(Mobdev2).Count);

        // An mDNS goodbye (the PTR re-advertised with TTL 0) evicts the pointer immediately, even though
        // its original TTL had two minutes left — a device announcing it is leaving drops out at once.
        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 0);
        Assert.AreEqual(0, cache.Resolve(Mobdev2).Count, "A TTL-0 goodbye must evict the instance immediately.");
    }

    [TestMethod]
    public void Prune_RemovesExpiredRecords_WithoutAffectingLiveOnes()
    {
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        // One short-lived instance and one long-lived one.
        const string shortInstance = "11:11:11:11:11:11@old._apple-mobdev2._tcp.local.";
        cache.AddPtr(Mobdev2, shortInstance, ttlSeconds: 5);
        cache.AddSrv(shortInstance, new Service("old.local.", 1), ttlSeconds: 5);
        cache.AddAddress("old.local.", new Address("192.168.68.1", "Wi-Fi"), ttlSeconds: 5);

        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 60);
        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 60);
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 60);

        Assert.AreEqual(2, cache.Resolve(Mobdev2).Count);

        clock.Advance(TimeSpan.FromSeconds(6));
        cache.Prune();

        var resolved = cache.Resolve(Mobdev2);
        Assert.AreEqual(1, resolved.Count, "Only the still-live instance survives a prune.");
        Assert.AreEqual(Instance, resolved[0].Instance);
    }

    [TestMethod]
    public void AddAddress_AccumulatesDistinctAddressesForSameHost()
    {
        FakeClock clock = new();
        MdnsRecordCache cache = new(() => clock.UtcNow);

        cache.AddPtr(Mobdev2, Instance, ttlSeconds: 60);
        cache.AddSrv(Instance, new Service(Host, 32498), ttlSeconds: 60);
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 60);
        cache.AddAddress(Host, new Address("fe80::ccdd:a6ff:feb4:ae24", "26"), ttlSeconds: 60);
        // Re-advertising the same IPv4 address must not duplicate it.
        cache.AddAddress(Host, new Address("192.168.68.82", "Wi-Fi"), ttlSeconds: 60);

        var resolved = cache.Resolve(Mobdev2);
        Assert.AreEqual(1, resolved.Count);
        Assert.AreEqual(2, resolved[0].Addresses.Count, "Two distinct addresses for the host; the duplicate IPv4 is not re-added.");
    }
}
