using System;

namespace Netimobiledevice.Lockdown;

/// <summary>
/// ScribeHold fork (#2198, P1-1): raised when a PER-CHUNK async socket write in
/// <see cref="ServiceConnection.SendAsync"/> exceeds the transport policy's write bound
/// (<see cref="Netimobiledevice.DeviceLink.TransportTimeoutPolicy.WriteBoundSec"/>). Async writes were
/// previously UNBOUNDED — <c>Stream.WriteTimeout</c> is sync-only in .NET — so a stalled <c>backupd</c>
/// could park a mid-Manifest.db 128 MiB DownloadFiles chunk write forever (the best-evidence mechanism
/// of the original 51-minute wedge; TCP keepalive cannot trip because the TCP peer is the local
/// usbmuxd, which stays alive even when the device side is wedged).
///
/// It derives from <see cref="TimeoutException"/> — exactly like
/// <c>DeviceLinkInterMessageTimeoutException</c> — so the host's existing
/// <c>catch (TimeoutException)</c> transient ladder (#2197) captures it and routes it into
/// reconnect-and-resume, while the dedicated type keeps it classifiable as a bounded transport-drop
/// signal (never a terminal failure, never a full-backup retry). Raised only when the policy enables
/// the bound (USB); WiFi disables it (<c>WriteBoundSec == 0</c>) so WiFi write behavior is untouched.
/// </summary>
public sealed class ServiceConnectionSendTimeoutException : TimeoutException
{
    public ServiceConnectionSendTimeoutException(TimeSpan bound)
        : base($"Timeout sending to service (per-chunk write bound {bound.TotalSeconds:0.###}s exceeded)")
    {
        Bound = bound;
    }

    /// <summary>The per-chunk write bound that was exceeded.</summary>
    public TimeSpan Bound { get; }
}
