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
    /// Dead-join detector threshold: an interface that had a live socket but received 0 FOREIGN packets for
    /// this many consecutive windows WHILE another interface received FOREIGN packets is treated as a dead
    /// join. Conservative so a quiet LAN does not thrash. (#1924 — counts FOREIGN, not self-echoes.)
    /// </summary>
    private const int DeadJoinWindows = 12;

    /// <summary>
    /// Minimum interval between dead-join rebinds. The detector previously rebound every ~8 windows and,
    /// because the rebind reset the receive state so the next windows again saw only self-echoes, formed a
    /// destructive churn loop (ScribeHold #1924). A long cooldown guarantees a rebind gets MANY stable
    /// windows to actually receive device responses before another dead-join rebind can fire — so a single
    /// genuine dead join still heals, but a mistaken trigger cannot loop. (Network-change rebinds are NOT
    /// subject to this cooldown — a real NIC transition rebinds immediately.)
    /// </summary>
    private static readonly TimeSpan DeadJoinRebindCooldown = TimeSpan.FromSeconds(90);

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
    // Per-interface consecutive-empty (no FOREIGN packet) window counters for the dead-join detector.
    private readonly Dictionary<int, int> _consecutiveEmpty = [];
    // Interfaces that have EVER received a FOREIGN packet (a real device response) in this browser's life.
    // Only such interfaces are dead-join candidates: an interface that has NEVER heard a device is simply a
    // wrong-subnet / VPN / virtual NIC with nothing on it (if 32/38/5/1/62 on the owner's host), NOT a dead
    // join — counting it churns forever (ScribeHold #1924). A genuine dead join is "was alive, went silent".
    private readonly HashSet<int> _everReceivedForeign = [];
    // When the last dead-join rebind fired, to enforce DeadJoinRebindCooldown and break churn (#1924).
    private DateTime _lastDeadJoinRebindUtc = DateTime.MinValue;

    // Instance names we have already announced as fully resolved, so the "resolved" log fires once per
    // device rather than every sweep.
    private readonly HashSet<string> _announced = new(StringComparer.OrdinalIgnoreCase);

    // OBSERVATION-ONLY (ScribeHold #1936): per-sweep heartbeat state. _sweepId counts receive windows so a
    // log line can be correlated to a sweep; _heartbeatTracker is the PURE deaf-NIC decision helper (warn
    // once after N consecutive zero-foreign sweeps, reset on activity). Neither affects discovery behavior.
    private int _sweepId;
    private readonly MdnsSweepHeartbeatTracker _heartbeatTracker = new();

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
                EmitSweepHeartbeat(result);
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
    /// Defense-in-depth dead-join detector, hardened against the #1924 churn loop.
    /// <para>
    /// Keys off FOREIGN packets only (real device responses). A multicast query we send loops back to every
    /// joined socket as a self-echo; counting those as "received" made an interface that heard ONLY its own
    /// echoes look alive, and — combined with rebinding every ~8 windows — formed a destructive loop:
    /// rebind → only echoes seen in the reset windows → "if26 got 0 (real)" → rebind again, forever, so
    /// device responses never got a stable window to land. The hardening:
    /// </para>
    /// <list type="number">
    /// <item>An interface clears its strikes when it receives a FOREIGN packet (self-echoes do not clear).</item>
    /// <item>Only an interface that has EVER received a foreign packet is a dead-join candidate. An interface
    /// that has never heard a device (a VPN / virtual / wrong-subnet NIC — if 32/38/5/1/62 on the owner's
    /// host) is not dead, it simply has no LAN devices on it; counting it churns forever. A genuine dead
    /// join is "was alive, then went silent while the device is still reachable elsewhere".</item>
    /// <item>A strike accrues only when SOME OTHER interface received a FOREIGN packet this window — the LAN
    /// is provably live. A globally quiet / echo-only window accrues nothing.</item>
    /// <item>A rebind fires at most once per <see cref="DeadJoinRebindCooldown"/>, so a rebind gets many
    /// stable windows to actually receive before another dead-join rebind can fire.</item>
    /// </list>
    /// </summary>
    private void EvaluateDeadJoins(MdnsBrowser.ReceiveWindowResult result) {
        if (result.BoundInterfaces is null || result.BoundInterfaces.Count == 0) {
            return;
        }
        // "LAN is live" = at least one interface received a FOREIGN packet (not just our own echoes).
        bool anyForeignReceived = result.ForeignPackets > 0;
        bool deadJoinFound = false;
        lock (_debounceLock) {
            foreach (int ifIndex in result.BoundInterfaces) {
                int foreign = result.PerInterfaceForeign is not null
                    && result.PerInterfaceForeign.TryGetValue(ifIndex, out int fc) ? fc : 0;
                if (foreign > 0) {
                    _consecutiveEmpty[ifIndex] = 0;
                    _everReceivedForeign.Add(ifIndex);
                    continue;
                }
                // An interface that has NEVER heard a device is not a dead join — it just has no LAN devices
                // on it (VPN/virtual/wrong-subnet). Never accrue strikes against it. This is the core #1924
                // fix: the previous detector mis-fired forever on the owner's if 32/38/5/1/62.
                if (!_everReceivedForeign.Contains(ifIndex)) {
                    continue;
                }
                // No foreign packet this window on an interface that WAS alive. Only count it when ANOTHER
                // interface heard a foreign packet (the LAN is live) — otherwise it is a quiet window.
                if (!anyForeignReceived) {
                    continue;
                }
                int strikes = _consecutiveEmpty.TryGetValue(ifIndex, out int s) ? s + 1 : 1;
                _consecutiveEmpty[ifIndex] = strikes;
                if (strikes >= DeadJoinWindows) {
                    deadJoinFound = true;
                    _logger.LogWarning(
                        "mDNS: if {Interface} was receiving but got 0 FOREIGN packets for {Strikes} consecutive windows while another interface received — candidate dead join",
                        ifIndex, strikes);
                }
            }

            if (deadJoinFound) {
                DateTime now = DateTime.UtcNow;
                if (now - _lastDeadJoinRebindUtc < DeadJoinRebindCooldown) {
                    // Within the cooldown — do NOT rebind (this is what breaks the churn loop). Leave the
                    // strikes in place; if the interface is truly dead it will rebind after the cooldown.
                    _logger.LogDebug(
                        "mDNS: dead-join candidate suppressed — within {Cooldown}s rebind cooldown (last {Ago:F0}s ago)",
                        DeadJoinRebindCooldown.TotalSeconds, (now - _lastDeadJoinRebindUtc).TotalSeconds);
                    deadJoinFound = false;
                }
                else {
                    _lastDeadJoinRebindUtc = now;
                }
            }
        }
        if (deadJoinFound) {
            _logger.LogWarning("mDNS: rebinding sockets (dead-join self-heal)");
            RequestRebind("dead-join detector");
        }
    }

    /// <summary>
    /// OBSERVATION-ONLY (ScribeHold #1936): emit the per-sweep mDNS heartbeat. This is the blind-spot fix —
    /// previously nothing reported per sweep, so an L2 receive deafness (the NIC stopped hearing device
    /// responses) was invisible. The PURE <see cref="MdnsSweepHeartbeatTracker"/> decides: when a sweep has
    /// foreign (real device-response) RX, log a Debug heartbeat with the per-interface counts; when N
    /// consecutive sweeps see ZERO foreign RX, log ONE Warning that the NIC is deaf (then suppress until
    /// activity resets the counter). Field names match the Service-side MdnsSweepHeartbeatEvent shape
    /// (<c>{SweepId}</c>, <c>{ForeignRxPackets}</c>, <c>{Resolved}</c>, <c>{InterfaceActivity}</c>) so both
    /// sources are queryable identically. The counter NEVER affects discovery behavior.
    /// </summary>
    private void EmitSweepHeartbeat(MdnsBrowser.ReceiveWindowResult result) {
        int sweepId = ++_sweepId;
        int foreignRx = result.ForeignPackets;
        int resolved = _cache.Resolve(_serviceType).Count;
        string interfaceActivity = DescribeInterfaceActivity(result);

        SweepHeartbeatDecision decision = _heartbeatTracker.Record(foreignRx);
        if (decision.EmitDeafWarning) {
            _logger.LogWarning(
                "mDNS NIC deaf for {Sweeps} consecutive sweeps (no foreign RX) — L2 receive blind spot; sweep={SweepId} foreignRxPackets={ForeignRxPackets} resolved={Resolved} interfaceActivity={InterfaceActivity}",
                decision.ConsecutiveZeroForeignSweeps, sweepId, foreignRx, resolved, interfaceActivity);
            return;
        }

        _logger.LogDebug(
            "mDNS sweep heartbeat sweep={SweepId} foreignRxPackets={ForeignRxPackets} resolved={Resolved} interfaceActivity={InterfaceActivity}",
            sweepId, foreignRx, resolved, interfaceActivity);
    }

    /// <summary>Build a compact "if=total/foreign" per-interface activity string for the heartbeat.</summary>
    private static string DescribeInterfaceActivity(MdnsBrowser.ReceiveWindowResult result) {
        if (result.BoundInterfaces is null || result.BoundInterfaces.Count == 0) {
            return "(none bound)";
        }
        List<string> parts = [];
        foreach (int ifIndex in result.BoundInterfaces) {
            int total = result.PerInterface is not null && result.PerInterface.TryGetValue(ifIndex, out int t) ? t : 0;
            int foreign = result.PerInterfaceForeign is not null && result.PerInterfaceForeign.TryGetValue(ifIndex, out int f) ? f : 0;
            parts.Add($"if{ifIndex}={total}/{foreign}");
        }
        return string.Join(", ", parts);
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
