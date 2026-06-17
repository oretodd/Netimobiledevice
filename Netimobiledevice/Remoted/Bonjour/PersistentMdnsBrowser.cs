using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// A long-lived mDNS browser for a single service type that RECEIVES CONTINUOUSLY and ACCUMULATES records
/// across sweeps, instead of opening fresh sockets, listening ~2s, and discarding state every poll.
///
/// <para>
/// This is the core of the ScribeHold #1914 round-7 fix. The polled mobdev2 discovery path called
/// <c>BrowseMobdev2Async</c> every ~5s, and each call built brand-new sockets, listened for ~2s, then
/// closed them — so (a) ~3s of every interval had no socket listening at all, and (b) records were
/// thrown away between sweeps, meaning a PTR received in one window and the matching SRV/A in the next
/// never combined into a resolved instance. The round-6 instrumentation proved the device adverts DO
/// arrive on the Wi-Fi interface, but a full PTR+SRV+A resolution rarely completed inside a single
/// 1000ms window, so almost every sweep reported "0 resolved instance(s)".
/// </para>
///
/// <para>
/// Here, one background loop keeps a receive permanently outstanding on the multicast sockets and feeds
/// every datagram into a persistent <see cref="MdnsRecordCache"/>. Queries are re-sent on an interval to
/// prompt responders, but resolution no longer depends on PTR/SRV/A landing in one window — a device is
/// resolved as soon as all three are simultaneously live in the cache, whichever sweep each arrived in.
/// A <see cref="SweepAsync"/> call sends a fresh query and returns the cache's currently-resolved set.
/// </para>
/// </summary>
public sealed class PersistentMdnsBrowser : IAsyncDisposable {
    /// <summary>How often the background loop re-sends the PTR query to prompt (re-)advertisement.</summary>
    private static readonly TimeSpan QueryInterval = TimeSpan.FromSeconds(2);

    private readonly string _serviceType;
    private readonly ILogger _logger;
    private readonly MdnsRecordCache _cache;
    private readonly MdnsBrowser _browser;
    private readonly byte[] _query;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _receiveLoop;
    private readonly object _logLock = new();

    // Instance names we have already announced as fully resolved, so the "resolved" log fires once per
    // device rather than every sweep.
    private readonly HashSet<string> _announced = new(StringComparer.OrdinalIgnoreCase);

    public PersistentMdnsBrowser(string serviceType, ILogger? logger = null, MdnsRecordCache? cache = null) {
        if (!serviceType.EndsWith('.')) {
            serviceType += ".";
        }
        _serviceType = serviceType;
        _logger = logger ?? NullLogger.Instance;
        _cache = cache ?? new MdnsRecordCache();
        _browser = new MdnsBrowser(_logger);
        _query = DnsHelpers.BuildQuery(_serviceType, DnsHelpers.QTYPE_PTR);
        _receiveLoop = Task.Run(() => RunReceiveLoopAsync(_cts.Token));
        _logger.LogInformation("mDNS persistent browser started for {ServiceType} (continuous receive)", _serviceType);
    }

    /// <summary>
    /// The background loop: keeps a receive permanently outstanding (via the shared
    /// <see cref="MdnsBrowser"/> engine) and re-arms it after each query interval, re-sending the query
    /// each time. Records flow into <see cref="_cache"/> as packets arrive — between sweeps as well as
    /// during them — which is the property the per-sweep browser lacked.
    /// </summary>
    private async Task RunReceiveLoopAsync(CancellationToken token) {
        try {
            while (!token.IsCancellationRequested) {
                await _browser.SendQuery(_query).ConfigureAwait(false);
                // Drain for one query interval, then loop to re-send. ReceiveIntoAsync returns when this
                // window's linked token fires; the records it deposited persist in the cache.
                using var window = CancellationTokenSource.CreateLinkedTokenSource(token);
                window.CancelAfter(QueryInterval);
                try {
                    await _browser.ReceiveIntoAsync(_cache, window.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) {
                    // Window or shutdown — fall through to re-evaluate the outer token.
                }
                _cache.Prune();
            }
        }
        catch (OperationCanceledException) {
            // Shutdown.
        }
        catch (Exception ex) {
            _logger.LogDebug(ex, "mDNS persistent receive loop ended unexpectedly for {ServiceType}", _serviceType);
        }
    }

    /// <summary>
    /// Prompt a fresh query and return the service instances currently resolved in the accumulated cache.
    /// Cheap and non-blocking relative to the old open/listen/close sweep — the listening is continuous
    /// in the background, so this just reads the latest assembled state.
    /// </summary>
    public List<ServiceInstance> SweepAsync() {
        List<ServiceInstance> resolved = _cache.Resolve(_serviceType);
        LogNewlyResolved(resolved);
        _logger.LogInformation(
            "mDNS persistent sweep {ServiceType}: {Instances} resolved instance(s) in cache",
            _serviceType, resolved.Count);
        return resolved;
    }

    /// <summary>
    /// Log each instance the FIRST time it becomes fully resolved (PTR+SRV+A complete), with its SRV host
    /// and addresses — the round-7 "resolution completing" datum that makes a real-device run self-evident.
    /// Drops instances from the announced set once they leave the resolved set so a device that disconnects
    /// and returns is logged again.
    /// </summary>
    private void LogNewlyResolved(List<ServiceInstance> resolved) {
        lock (_logLock) {
            HashSet<string> current = new(resolved.Select(r => r.Instance), StringComparer.OrdinalIgnoreCase);
            foreach (ServiceInstance si in resolved) {
                if (_announced.Add(si.Instance)) {
                    _logger.LogInformation(
                        "mDNS instance fully resolved: {Instance} -> {Host}:{Port} at [{Addresses}]",
                        si.Instance, si.Host, si.Port, string.Join(", ", si.Addresses.Select(a => a.FullIp)));
                }
            }
            _announced.RemoveWhere(name => !current.Contains(name));
        }
    }

    public async ValueTask DisposeAsync() {
        _cts.Cancel();
        try {
            await _receiveLoop.ConfigureAwait(false);
        }
        catch {
            // The loop is cancellation-driven; any residual exception on shutdown is expected.
        }
        _browser.DropAndClose();
        _cts.Dispose();
    }
}
