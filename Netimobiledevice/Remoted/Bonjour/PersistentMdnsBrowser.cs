using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
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

    /// <summary>
    /// Coalesce a burst of network-change events (NordLynx/Wi-Fi reconnect emits several in quick
    /// succession) into a single rebind fired this long after the LAST event in the burst.
    /// </summary>
    private static readonly TimeSpan RebindDebounce = TimeSpan.FromSeconds(2.5);

    /// <summary>
    /// Dead-join detector threshold: if an interface that HAD a live socket received 0 packets for this
    /// many consecutive windows WHILE some other interface was receiving, rebind to drop+rejoin it.
    /// Conservative (a healthy idle LAN can be quiet for a few windows) to avoid thrashing.
    /// </summary>
    private const int DeadJoinWindows = 8;

    private readonly string _serviceType;
    private readonly ILogger _logger;
    private readonly MdnsRecordCache _cache;
    private readonly MdnsBrowser _browser;
    private readonly byte[] _query;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _receiveLoop;
    private readonly object _logLock = new();

    // Network-change self-heal state. _rebindRequested is set by the (debounced) network-change handler
    // and by the dead-join detector; the receive loop services it. _windowCts lets the handler/rebind
    // CANCEL the current receive window so the loop re-snapshots the fresh sockets immediately instead of
    // draining the rest of a window on dead sockets.
    private volatile CancellationTokenSource? _windowCts;
    private int _rebindRequested; // 0/1 via Interlocked
    private readonly object _debounceLock = new();
    private Timer? _debounceTimer;
    private bool _networkSubscribed;
    // Per-interface consecutive-empty-window counters for the dead-join detector.
    private readonly Dictionary<int, int> _consecutiveEmpty = [];

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

        // Self-heal: rebind sockets on a network change (the #1923 fix — a join made while NordLynx was
        // mid-reconnect stays dead forever otherwise). Both NIC-address and availability transitions are
        // relevant; debounce coalesces the burst. The browser also raises SocketsRebound after a rebind so
        // the loop drops its current (now-disposed) window immediately.
        _browser.SocketsRebound += OnSocketsRebound;
        try {
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
            _networkSubscribed = true;
        }
        catch (Exception ex) {
            // NetworkChange can be unavailable in some hosting contexts; degrade to no auto-rebind rather
            // than failing construction (the dead-join detector still provides a recovery path).
            _logger.LogDebug(ex, "mDNS: NetworkChange subscription unavailable; relying on dead-join detector");
        }

        _receiveLoop = Task.Run(() => RunReceiveLoopAsync(_cts.Token));
        _logger.LogInformation("mDNS persistent browser started for {ServiceType} (continuous receive, self-heal on network change)", _serviceType);
    }

    private void OnNetworkChanged(object? sender, EventArgs e) => ScheduleRebind("address change");
    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e) => ScheduleRebind("availability change");

    /// <summary>
    /// Debounce a network-change burst into a single rebind. Each event (re)arms a one-shot timer for
    /// <see cref="RebindDebounce"/>; only the last event in a burst actually fires RequestRebind.
    /// </summary>
    private void ScheduleRebind(string reason) {
        lock (_debounceLock) {
            _logger.LogDebug("mDNS: network {Reason} observed; debouncing rebind ({Debounce}s)", reason, RebindDebounce.TotalSeconds);
            _debounceTimer ??= new Timer(_ => RequestRebind(reason), null, Timeout.Infinite, Timeout.Infinite);
            _debounceTimer.Change(RebindDebounce, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>Signal the receive loop to rebind, and break the current window so it acts at once.</summary>
    private void RequestRebind(string reason) {
        Interlocked.Exchange(ref _rebindRequested, 1);
        _logger.LogInformation("mDNS: requesting socket rebind ({Reason})", reason);
        try { _windowCts?.Cancel(); } catch (ObjectDisposedException) { /* loop between windows */ }
    }

    /// <summary>After the browser rebuilds sockets, drop the current window so the loop re-snapshots them.</summary>
    private void OnSocketsRebound() {
        try { _windowCts?.Cancel(); } catch (ObjectDisposedException) { /* loop between windows */ }
    }

    /// <summary>
    /// The background loop: keeps a receive permanently outstanding (via the shared
    /// <see cref="MdnsBrowser"/> engine) and re-arms it after each query interval, re-sending the query
    /// each time. Records flow into <see cref="_cache"/> as packets arrive — between sweeps as well as
    /// during them — which is the property the per-sweep browser lacked. Between windows it services any
    /// pending rebind request (network change or dead-join) so a dead-on-arrival interface heals.
    /// </summary>
    private async Task RunReceiveLoopAsync(CancellationToken token) {
        try {
            while (!token.IsCancellationRequested) {
                // Service a pending rebind BEFORE sending/receiving this window.
                if (Interlocked.Exchange(ref _rebindRequested, 0) == 1) {
                    SafeRebind();
                }

                await _browser.SendQuery(_query).ConfigureAwait(false);
                // Drain for one query interval, then loop to re-send. ReceiveIntoAsync returns when this
                // window's linked token fires; the records it deposited persist in the cache. The window
                // token is exposed via _windowCts so a network-change/rebind can break it early.
                using var window = CancellationTokenSource.CreateLinkedTokenSource(token);
                window.CancelAfter(QueryInterval);
                _windowCts = window;
                MdnsBrowser.ReceiveWindowResult result = default;
                try {
                    result = await _browser.ReceiveIntoAsync(_cache, window.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) {
                    // Window elapsed, rebind-break, or shutdown — fall through to re-evaluate the outer token.
                }
                finally {
                    _windowCts = null;
                }
                _cache.Prune();
                EvaluateDeadJoins(result);
            }
        }
        catch (OperationCanceledException) {
            // Shutdown.
        }
        catch (Exception ex) {
            _logger.LogDebug(ex, "mDNS persistent receive loop ended unexpectedly for {ServiceType}", _serviceType);
        }
    }

    /// <summary>Rebind the browser's sockets, swallowing any error so the loop keeps running.</summary>
    private void SafeRebind() {
        try {
            _browser.RebindSockets();
            lock (_debounceLock) {
                _consecutiveEmpty.Clear();
            }
        }
        catch (Exception ex) {
            _logger.LogWarning(ex, "mDNS: socket rebind failed; will retry on next trigger");
        }
    }

    /// <summary>
    /// Defense-in-depth dead-join detector: per window, an interface that had a live socket but received 0
    /// packets accrues a strike; one that received clears its strikes. If ANY interface hits
    /// <see cref="DeadJoinWindows"/> consecutive empty windows WHILE another interface received this window
    /// (proving the LAN is live), request a rebind to drop+rejoin. The "another interface received" guard
    /// keeps a globally-quiet LAN from triggering pointless rebinds.
    /// </summary>
    private void EvaluateDeadJoins(MdnsBrowser.ReceiveWindowResult result) {
        if (result.BoundInterfaces is null || result.BoundInterfaces.Count == 0) {
            return;
        }
        bool anyReceived = result.Packets > 0;
        bool deadJoinFound = false;
        lock (_debounceLock) {
            foreach (int ifIndex in result.BoundInterfaces) {
                int got = result.PerInterface.TryGetValue(ifIndex, out int c) ? c : 0;
                if (got > 0) {
                    _consecutiveEmpty[ifIndex] = 0;
                    continue;
                }
                // Only count an empty window against an interface when SOME interface received (LAN is live).
                if (!anyReceived) {
                    continue;
                }
                int strikes = _consecutiveEmpty.TryGetValue(ifIndex, out int s) ? s + 1 : 1;
                _consecutiveEmpty[ifIndex] = strikes;
                if (strikes >= DeadJoinWindows) {
                    deadJoinFound = true;
                    _logger.LogWarning(
                        "mDNS: if {Interface} received 0 packets for {Strikes} consecutive windows while other interfaces received — rebinding (dead-join self-heal)",
                        ifIndex, strikes);
                }
            }
        }
        if (deadJoinFound) {
            RequestRebind("dead-join detector");
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
        // Unsubscribe from network-change events and stop the debounce timer FIRST so nothing schedules a
        // rebind during teardown.
        if (_networkSubscribed) {
            try {
                NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
                NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            }
            catch {
                // Best effort: unsubscribing a never-fully-subscribed event can throw in odd hosts.
            }
            _networkSubscribed = false;
        }
        _browser.SocketsRebound -= OnSocketsRebound;
        lock (_debounceLock) {
            _debounceTimer?.Dispose();
            _debounceTimer = null;
        }

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
