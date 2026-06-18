using System;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// OBSERVATION-ONLY (ScribeHold #1936). A tiny PURE decision helper for the per-sweep mDNS heartbeat: it
/// counts consecutive sweeps with ZERO foreign (real device-response) RX packets and decides when to emit
/// a single "NIC deaf" warning. It NEVER touches sockets, discovery, or the cache — it only classifies the
/// per-sweep foreign-packet count so the receive loop can log the right level. Pure and side-effect free,
/// so the equivalent logic is unit-testable without the submodule.
/// </summary>
internal sealed class MdnsSweepHeartbeatTracker {
    /// <summary>
    /// Consecutive zero-foreign-RX sweeps before a single deaf-NIC warning is emitted. Conservative so a
    /// briefly-quiet LAN does not warn. After the warning fires it is suppressed until foreign activity
    /// resets the counter (so the log is not spammed every sweep).
    /// </summary>
    public const int DefaultDeafSweepThreshold = 3;

    private readonly int _threshold;
    private int _consecutiveZeroForeign;
    private bool _warned;

    public MdnsSweepHeartbeatTracker(int threshold = DefaultDeafSweepThreshold) {
        if (threshold < 1) {
            throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "threshold must be >= 1");
        }
        _threshold = threshold;
    }

    /// <summary>The number of consecutive zero-foreign sweeps observed so far.</summary>
    public int ConsecutiveZeroForeign => _consecutiveZeroForeign;

    /// <summary>
    /// Record one sweep's foreign-RX packet count and return the heartbeat decision.
    /// <para>
    /// When <paramref name="foreignRxPackets"/> &gt; 0 the deaf counter resets and any prior warning is
    /// re-armed (so a future deaf streak warns again); the decision is a plain Debug heartbeat.
    /// </para>
    /// <para>
    /// When it is 0 the counter increments; the decision becomes a single Warning exactly on the sweep that
    /// FIRST reaches the threshold, and Debug heartbeats thereafter until activity resets it.
    /// </para>
    /// </summary>
    public SweepHeartbeatDecision Record(int foreignRxPackets) {
        if (foreignRxPackets > 0) {
            _consecutiveZeroForeign = 0;
            _warned = false;
            return new SweepHeartbeatDecision(emitDeafWarning: false, _consecutiveZeroForeign);
        }

        _consecutiveZeroForeign++;
        if (_consecutiveZeroForeign >= _threshold && !_warned) {
            _warned = true;
            return new SweepHeartbeatDecision(emitDeafWarning: true, _consecutiveZeroForeign);
        }
        return new SweepHeartbeatDecision(emitDeafWarning: false, _consecutiveZeroForeign);
    }
}

/// <summary>The pure outcome of one <see cref="MdnsSweepHeartbeatTracker.Record"/> call.</summary>
internal readonly struct SweepHeartbeatDecision(bool emitDeafWarning, int consecutiveZeroForeignSweeps) {
    /// <summary>True on the single sweep that crosses the deaf threshold (warn once, then suppress).</summary>
    public bool EmitDeafWarning { get; } = emitDeafWarning;
    /// <summary>Consecutive zero-foreign-RX sweeps after this sweep.</summary>
    public int ConsecutiveZeroForeignSweeps { get; } = consecutiveZeroForeignSweeps;
}
