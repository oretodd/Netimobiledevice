using Netimobiledevice.Plist;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.DeviceLink;

/// <summary>
/// ScribeHold fork (#2181): the delegate that actually writes a terminating
/// <c>DLMessageStatusResponse</c> onto the mb2 service channel. Kept as a narrow function type so the
/// response-guarantee is decoupled from <see cref="DeviceLinkService"/> internals and is unit-testable
/// against a capturing fake sender (no live socket).
/// </summary>
/// <param name="errorCode">The errno-style status code (0 = success).</param>
/// <param name="errorMessage">Optional error message; null/empty sends the empty-parameter sentinel.</param>
/// <param name="payload">Optional additional value node (e.g. a directory listing or free-space integer).</param>
/// <param name="cancellationToken">The token to pass to the underlying send.</param>
public delegate Task DeviceLinkStatusSender(int errorCode, string? errorMessage, PropertyNode? payload, CancellationToken cancellationToken);

/// <summary>
/// ScribeHold fork (#2181): guarantees a DeviceLink handler discharges its
/// <c>DLMessageStatusResponse</c> obligation exactly once, even if the handler's cancellation token
/// trips mid-body. The handler honors cancellation for its own loop work (enumerate / move / remove),
/// but the terminating status is ALWAYS sent — on <see cref="CancellationToken.None"/> if necessary —
/// before the cancellation is propagated, so the device is never left blocking.
///
/// Send-exactly-once is latched internally: a second terminating send is a no-op.
/// </summary>
public interface IDeviceLinkResponseGuarantee : IAsyncDisposable
{
    /// <summary>True once a terminating response has been sent (latched).</summary>
    bool Responded { get; }

    /// <summary>
    /// Sends the terminating status report exactly once. Safe to call from a finally/catch on
    /// <see cref="CancellationToken.None"/>; a second call is a no-op.
    /// </summary>
    Task SendTerminatingStatusAsync(int errorCode, string? errorMessage, PropertyNode? payload, CancellationToken cancellationToken);
}

/// <summary>
/// ScribeHold fork (#2181): the concrete response-guarantee. This is the SINGLE testable place where
/// "a handler owes exactly one terminating DLMessageStatusResponse" lives — replacing the
/// per-handler <c>if (!cancellationToken.IsCancellationRequested) { send } ... break</c> shape that
/// let a mid-handler cancel return WITHOUT responding, deadlocking the device against
/// <see cref="DeviceLinkService.DlLoop"/> (the silent <c>Backup_Preparing</c> wedge).
///
/// Lifecycle: created per handled message via <see cref="DeviceLinkResponseGuarantees.For"/>, used
/// with <c>await using</c> inside the handler. If the handler sends its response explicitly, dispose
/// is a no-op; if the handler returns (or throws / is cancelled) WITHOUT responding,
/// <see cref="DisposeAsync"/> discharges a default success terminating status on
/// <see cref="CancellationToken.None"/> so no code path leaves the device blocking.
/// </summary>
public sealed class DeviceLinkResponseGuarantee : IDeviceLinkResponseGuarantee
{
    private readonly DeviceLinkStatusSender _sender;
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    // Latch: 0 = not yet responded, 1 = responded. Guarded by _sendGate for the send itself and read
    // lock-free via Volatile for the public Responded property.
    private int _responded;

    public DeviceLinkResponseGuarantee(DeviceLinkStatusSender sender)
    {
        _sender = sender ?? throw new ArgumentNullException(nameof(sender));
    }

    public bool Responded => Volatile.Read(ref _responded) == 1;

    public async Task SendTerminatingStatusAsync(int errorCode, string? errorMessage, PropertyNode? payload, CancellationToken cancellationToken)
    {
        // Serialize sends and enforce send-exactly-once. The gate also guards against a racing
        // DisposeAsync default-send: whichever acquires the gate first latches, the other becomes a
        // no-op. A single failed send does NOT latch, so a later attempt (e.g. the dispose fallback)
        // can still try to discharge the obligation.
        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try {
            if (Volatile.Read(ref _responded) == 1) {
                return;
            }
            await _sender(errorCode, errorMessage, payload, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _responded, 1);
        }
        finally {
            _sendGate.Release();
        }
    }

    /// <summary>
    /// If the handler never sent its terminating response (returned early on a <c>break</c>, threw, or
    /// was cancelled mid-body), discharge a default success terminating status on
    /// <see cref="CancellationToken.None"/> so the device is never left blocking. Sent on
    /// <see cref="CancellationToken.None"/> deliberately: the very reason the handler failed to respond
    /// is usually that ITS token was cancelled, and the response must still go out before the
    /// cancellation propagates.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Volatile.Read(ref _responded) != 1) {
            try {
                await SendTerminatingStatusAsync(0, null, null, CancellationToken.None).ConfigureAwait(false);
            }
            catch {
                // Best-effort: the socket may already be gone (the same drop that cancelled the
                // handler). We must never let the dispose fallback throw over the handler's own
                // in-flight exception (e.g. the propagating OperationCanceledException).
            }
        }
        _sendGate.Dispose();
    }
}

/// <summary>
/// ScribeHold fork (#2181): the factory/owner <see cref="DeviceLinkService"/> holds to hand a fresh
/// <see cref="IDeviceLinkResponseGuarantee"/> to each handled message. Injecting the
/// <see cref="DeviceLinkStatusSender"/> once (bound to <c>SendStatusReport</c>) keeps the guarantee
/// decoupled from the service and lets a test substitute a capturing sender.
/// </summary>
public sealed class DeviceLinkResponseGuarantees
{
    private readonly DeviceLinkStatusSender _sender;

    public DeviceLinkResponseGuarantees(DeviceLinkStatusSender sender)
    {
        _sender = sender ?? throw new ArgumentNullException(nameof(sender));
    }

    /// <summary>
    /// Create a response-guarantee for a single handled message. Use with <c>await using</c> so a
    /// handler that returns without responding still discharges its obligation at dispose.
    /// </summary>
    public IDeviceLinkResponseGuarantee Create() => new DeviceLinkResponseGuarantee(_sender);
}
