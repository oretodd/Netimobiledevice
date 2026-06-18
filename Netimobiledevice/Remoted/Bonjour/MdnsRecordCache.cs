using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// Accumulates mDNS resource records (PTR / SRV / TXT / A / AAAA) ACROSS browse sweeps and resolves
/// complete service instances from the accumulated state.
///
/// <para>
/// This is the fix for ScribeHold #1914 QA round 7. The previous browser was stateless per sweep: each
/// ~2s <c>BrowseMobdev2Async</c> call built a fresh PTR/SRV/A map and discarded it on return. mDNS
/// responses are asynchronous — a device's PTR, SRV, and A records often arrive in separate packets and
/// even separate sweeps — so a PTR seen in sweep N and the matching SRV in sweep N+1 never combined, and
/// almost every 1000ms window reported "0 resolved instance(s)" even when device adverts were proven
/// (by the round-6 instrumentation) to be arriving on the Wi-Fi interface. Holding the records in a
/// cache that survives between sweeps lets a device resolve once its PTR has a live SRV and at least one
/// live address, regardless of which sweep each record arrived in.
/// </para>
///
/// <para>
/// Records expire on their advertised TTL, and an mDNS "goodbye" (a record re-advertised with TTL 0)
/// evicts immediately, so a device that goes off the LAN drops out of the resolved set rather than
/// lingering forever. The cache is keyed by record owner name and is safe for a single producer
/// (the receive loop) plus readers (sweep resolution) via a coarse lock — mDNS volumes are tiny.
/// </para>
/// </summary>
public sealed class MdnsRecordCache : IMdnsRecordSink {
    // A cached record carries the value plus the absolute instant it expires (now + TTL at insert).
    private readonly struct Expiring<T>(T value, DateTime expiresAtUtc) {
        public T Value { get; } = value;
        public DateTime ExpiresAtUtc { get; } = expiresAtUtc;
        public bool IsLive(DateTime nowUtc) => ExpiresAtUtc > nowUtc;
    }

    private readonly object _lock = new();
    private readonly Func<DateTime> _utcNow;
    // OBSERVATION-ONLY (ScribeHold #1936): Trace-level L2 RX observation logger. Defaults to NullLogger so
    // existing call sites (and tests) that construct the cache with no logger are unaffected. Logging here
    // records record arrivals/goodbyes; it never changes the eviction policy or any cache logic.
    private readonly ILogger _logger;

    // PTR: service type (e.g. "_apple-mobdev2._tcp.local.") -> set of instance names it points at.
    private readonly Dictionary<string, Dictionary<string, Expiring<bool>>> _ptr = new(StringComparer.OrdinalIgnoreCase);
    // SRV: instance name -> the target host + port (latest advertised, with its expiry).
    private readonly Dictionary<string, Expiring<Service>> _srv = new(StringComparer.OrdinalIgnoreCase);
    // TXT: instance name -> key/value properties.
    private readonly Dictionary<string, Expiring<Dictionary<string, string>>> _txt = new(StringComparer.OrdinalIgnoreCase);
    // Addresses: host name (the SRV target) -> distinct addresses (by FullIp), each with its expiry.
    private readonly Dictionary<string, Dictionary<string, Expiring<Address>>> _addr = new(StringComparer.OrdinalIgnoreCase);

    public MdnsRecordCache(ILogger? logger = null) : this(static () => DateTime.UtcNow, logger) { }

    /// <summary>Test seam: inject a deterministic clock so TTL/expiry behaviour is verifiable.</summary>
    public MdnsRecordCache(Func<DateTime> utcNow, ILogger? logger = null) {
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// A PTR record: <paramref name="serviceType"/> points at <paramref name="instance"/>. A TTL of 0 is
    /// an mDNS goodbye — the pointer is evicted immediately.
    /// </summary>
    public void AddPtr(string serviceType, string instance, uint ttlSeconds) {
        lock (_lock) {
            if (ttlSeconds == 0) {
                if (_ptr.TryGetValue(serviceType, out Dictionary<string, Expiring<bool>>? targets)) {
                    targets.Remove(instance);
                }
                // OBSERVATION-ONLY (#1936): L2 RX goodbye/eviction. Trace level, no policy change.
                _logger.LogTrace("[mdns-rx] evict {Type} {Name} (goodbye, ttl=0) for {Instance}", "PTR", serviceType, instance);
                return;
            }
            if (!_ptr.TryGetValue(serviceType, out Dictionary<string, Expiring<bool>>? map)) {
                map = new Dictionary<string, Expiring<bool>>(StringComparer.OrdinalIgnoreCase);
                _ptr[serviceType] = map;
            }
            map[instance] = new Expiring<bool>(true, ExpiryFrom(ttlSeconds));
            // OBSERVATION-ONLY (#1936): L2 RX record insert. Trace level, no policy change.
            _logger.LogTrace("[mdns-rx] insert {Type} {Name} -> {Instance} (ttl {Ttl}s)", "PTR", serviceType, instance, ttlSeconds);
        }
    }

    public void AddSrv(string instance, Service service, uint ttlSeconds) {
        lock (_lock) {
            if (ttlSeconds == 0) {
                _srv.Remove(instance);
                return;
            }
            _srv[instance] = new Expiring<Service>(service, ExpiryFrom(ttlSeconds));
        }
    }

    public void AddTxt(string instance, Dictionary<string, string> properties, uint ttlSeconds) {
        lock (_lock) {
            if (ttlSeconds == 0) {
                _txt.Remove(instance);
                return;
            }
            _txt[instance] = new Expiring<Dictionary<string, string>>(properties, ExpiryFrom(ttlSeconds));
        }
    }

    public void AddAddress(string host, Address address, uint ttlSeconds) {
        lock (_lock) {
            if (!_addr.TryGetValue(host, out Dictionary<string, Expiring<Address>>? map)) {
                map = new Dictionary<string, Expiring<Address>>(StringComparer.OrdinalIgnoreCase);
                _addr[host] = map;
            }
            string key = address.FullIp;
            if (ttlSeconds == 0) {
                map.Remove(key);
                // OBSERVATION-ONLY (#1936): L2 RX address goodbye/eviction. Trace level, no policy change.
                _logger.LogTrace("[mdns-rx] evict {Type} {Name} {Ip} (goodbye, ttl=0)", "A/AAAA", host, key);
                return;
            }
            map[key] = new Expiring<Address>(address, ExpiryFrom(ttlSeconds));
            // OBSERVATION-ONLY (#1936): L2 RX address insert. Trace level, no policy change.
            _logger.LogTrace("[mdns-rx] insert {Type} {Name} {Ip} (ttl {Ttl}s)", "A/AAAA", host, key, ttlSeconds);
        }
    }

    /// <summary>
    /// Resolve the currently-complete instances of <paramref name="serviceType"/>: every PTR target that
    /// has a live SRV and at least one live address. A device is "discovered" the moment all three are
    /// simultaneously live in the cache, even if the PTR, SRV, and A records arrived across different
    /// sweeps — which is exactly what a single short browse window could not guarantee.
    /// </summary>
    public List<ServiceInstance> Resolve(string serviceType) {
        lock (_lock) {
            DateTime now = _utcNow();
            List<ServiceInstance> resolved = [];
            if (!_ptr.TryGetValue(serviceType, out Dictionary<string, Expiring<bool>>? targets)) {
                return resolved;
            }

            foreach ((string instance, Expiring<bool> ptr) in targets) {
                if (!ptr.IsLive(now)) {
                    continue;
                }
                if (!_srv.TryGetValue(instance, out Expiring<Service> srv) || !srv.IsLive(now)) {
                    continue;
                }
                List<Address> liveAddrs = LiveAddressesFor(srv.Value.Target, now);
                if (liveAddrs.Count == 0) {
                    continue;
                }

                resolved.Add(new ServiceInstance(instance) {
                    Host = srv.Value.Target.TrimEnd('.'),
                    Port = srv.Value.Port,
                    Addresses = liveAddrs,
                    Properties = (_txt.TryGetValue(instance, out Expiring<Dictionary<string, string>> txt) && txt.IsLive(now))
                        ? txt.Value
                        : []
                });
            }
            return resolved;
        }
    }

    /// <summary>
    /// Satisfies <see cref="IMdnsRecordSink"/>; the cache does not track parse failures itself (the
    /// persistent browser logs them from the receive loop), so this is intentionally a no-op.
    /// </summary>
    public void RecordParseFailure() { }

    /// <summary>Drop every expired record. Cheap to call each sweep; keeps the maps from growing without bound.</summary>
    public void Prune() {
        lock (_lock) {
            DateTime now = _utcNow();
            PruneNested(_ptr, now);
            PruneFlat(_srv, now);
            PruneFlat(_txt, now);
            PruneNested(_addr, now);
        }
    }

    private List<Address> LiveAddressesFor(string host, DateTime now) {
        if (!_addr.TryGetValue(host, out Dictionary<string, Expiring<Address>>? map)) {
            return [];
        }
        return [.. map.Values.Where(a => a.IsLive(now)).Select(a => a.Value)];
    }

    private DateTime ExpiryFrom(uint ttlSeconds) {
        // mDNS TTLs can be large (the mobdev2 default is 2 hours); cap the cached lifetime so a device
        // that silently drops off the LAN (no goodbye) still ages out within a sweep or two of being gone,
        // and so a stale address can never outlive a reasonable reconnection window.
        const uint maxTtlSeconds = 120;
        uint effective = Math.Min(ttlSeconds, maxTtlSeconds);
        return _utcNow().AddSeconds(effective);
    }

    private static void PruneFlat<T>(Dictionary<string, Expiring<T>> map, DateTime now) {
        List<string> dead = [.. map.Where(kvp => !kvp.Value.IsLive(now)).Select(kvp => kvp.Key)];
        foreach (string key in dead) {
            map.Remove(key);
        }
    }

    private static void PruneNested<T>(Dictionary<string, Dictionary<string, Expiring<T>>> outer, DateTime now) {
        List<string> emptyOuter = [];
        foreach ((string outerKey, Dictionary<string, Expiring<T>> inner) in outer) {
            List<string> dead = [.. inner.Where(kvp => !kvp.Value.IsLive(now)).Select(kvp => kvp.Key)];
            foreach (string key in dead) {
                inner.Remove(key);
            }
            if (inner.Count == 0) {
                emptyOuter.Add(outerKey);
            }
        }
        foreach (string key in emptyOuter) {
            outer.Remove(key);
        }
    }
}
