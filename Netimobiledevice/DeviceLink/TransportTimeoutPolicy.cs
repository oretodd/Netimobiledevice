using System;
using System.Threading;

namespace Netimobiledevice.DeviceLink;

/// <summary>
/// ScribeHold fork (#2182): the named transport-timeout policy. A single value object that carries
/// every transport-sensitive bound the relay uses -- the bulk-read timeout, the TCP keepalive budget
/// (Time/Interval/RetryCount, #1857), the SSL-handshake watchdog bound (#1999 previously
/// <see cref="Timeout.Infinite"/>), and the DlLoop inter-message silence bound (consumed by Task 1)
/// -- selected once per transport so there are no inline "USB vs WiFi" branches scattered through
/// <see cref="Netimobiledevice.Lockdown.ServiceConnection"/>.
///
/// USB (usbmux) is the reliability-critical transport in ScribeHold: it is the primary path, and a
/// wedged USB backup must FAIL FAST INTO RECOVERY rather than hang. WiFi keeps its existing loose
/// values (#1926 tight lockdown timeouts, #2081 finished-latch loop timing) untouched -- this fork
/// adds no WiFi resilience and makes no gratuitous WiFi change. The library default is
/// <see cref="UsbTight"/> so a standalone submodule consumer is safe; the hosting ScribeHold.Service
/// overrides the concrete thresholds from <c>BackupConfiguration</c> (Task 3) and passes them down.
///
/// This is a real named collaborator (rules/decomposition-not-partials.md): a new public type with a
/// single responsibility (own the transport bounds), a narrow surface, and readable standalone.
/// <see cref="ServiceConnection"/> HOLDS an instance and DELEGATES to it.
/// </summary>
public sealed class TransportTimeoutPolicy
{
    /// <summary>
    /// The bulk-read timeout in milliseconds applied to the data stream via
    /// <see cref="Netimobiledevice.Lockdown.ServiceConnection.SetTimeout(int)"/>. USB is tighter than
    /// WiFi so a stalled USB read is surfaced (and fed into reconnect-and-resume) sooner. May be
    /// <see cref="Timeout.Infinite"/> for callers that manage the read budget themselves.
    /// </summary>
    public int ReadTimeoutMs { get; }

    /// <summary>
    /// TCP keepalive idle time in SECONDS before the first probe (<c>TcpKeepAliveTime</c>). #1857.
    /// </summary>
    public int KeepAliveTimeSec { get; }

    /// <summary>
    /// TCP keepalive interval in SECONDS between probes (<c>TcpKeepAliveInterval</c>). #1857.
    /// </summary>
    public int KeepAliveIntervalSec { get; }

    /// <summary>
    /// TCP keepalive probe count before the stack declares the socket dead
    /// (<c>TcpKeepAliveRetryCount</c>). #1857.
    /// </summary>
    public int KeepAliveRetryCount { get; }

    /// <summary>
    /// The SSL-handshake watchdog bound in SECONDS. #1999 previously ran the handshake with
    /// <see cref="Timeout.Infinite"/> so a device trust/passcode dialog could not abort the socket;
    /// that is preserved for the dialog window, but a lost <c>close_notify</c> during the handshake
    /// could then hang forever. This bound caps ONLY the SSL wait -- it FEEDS reconnect-and-resume,
    /// it does NOT shorten the passcode dialog window (the dialog is a NotificationProxy concern on a
    /// different channel, not the SSL stream wait bounded here).
    /// </summary>
    public int SslHandshakeWatchdogSec { get; }

    /// <summary>
    /// The DlLoop inter-message silence bound in SECONDS: how long the loop tolerates the device
    /// going silent BETWEEN messages before raising a bounded, classifiable transport-drop signal
    /// (consumed by Task 1's DeviceLinkService). USB-tight so a between-message wedge fails in seconds
    /// and feeds reconnect, rather than waiting out the 10-minute bulk-read timeout. Exposed here so
    /// the single policy owns every transport bound; Task 1 reads it from the same policy.
    ///
    /// <para>#2193: this TIGHT bound governs ONLY the in-transfer phase (after the device begins
    /// pushing real backup-file content). During the pre-first-file <c>Preparing</c> window the device
    /// legitimately goes silent for MINUTES while it builds its on-device manifest diff, so the DlLoop
    /// applies the generous <see cref="PreparingSilenceBoundSec"/> instead — the tight bound here must
    /// not interrupt a healthy Preparing diff.</para>
    /// </summary>
    public int InterMessageSilenceBoundSec { get; }

    /// <summary>
    /// #2193: the PRE-first-file <c>Preparing</c>-phase silence bound in SECONDS — generous (minutes),
    /// because a healthy device goes silent for several minutes while it builds its on-device manifest
    /// diff before any real backup-file transfer begins. The DlLoop applies THIS bound (not the tight
    /// <see cref="InterMessageSilenceBoundSec"/>) until the first real <c>FileReceiving</c> event, then
    /// switches to the tight in-transfer bound. This is the safeguard the plan designed as a "distinct,
    /// generous Preparing bound" (host key <c>BackupConfiguration.UsbPreparingStallThresholdSec</c>);
    /// the library default keeps it comfortably above the tight bound so a standalone consumer never
    /// interrupts a normal diff. Only applied on USB (WiFi keeps its single loose bound).
    /// </summary>
    public int PreparingSilenceBoundSec { get; }

    /// <summary>
    /// The keepalive budget in seconds implied by the keepalive settings
    /// (<c>Time + Interval * RetryCount</c>). Diagnostic/convenience; #1857 sized this to ~7 min on
    /// USB, kept under the DeviceLinkService bulk-read timeout.
    /// </summary>
    public int KeepAliveBudgetSec => KeepAliveTimeSec + (KeepAliveIntervalSec * KeepAliveRetryCount);

    /// <param name="readTimeoutMs">Bulk-read timeout in ms (or <see cref="Timeout.Infinite"/>).</param>
    /// <param name="keepAliveTimeSec">TCP keepalive idle time before the first probe (seconds).</param>
    /// <param name="keepAliveIntervalSec">TCP keepalive interval between probes (seconds).</param>
    /// <param name="keepAliveRetryCount">TCP keepalive probe count before the socket is declared dead.</param>
    /// <param name="sslHandshakeWatchdogSec">SSL-handshake watchdog bound (seconds); bounds ONLY the SSL wait.</param>
    /// <param name="interMessageSilenceBoundSec">DlLoop inter-message silence bound (seconds) — the TIGHT in-transfer bound.</param>
    /// <param name="preparingSilenceBoundSec">
    /// #2193: the generous pre-first-file <c>Preparing</c>-phase silence bound (seconds). Defaults to
    /// <see cref="DefaultPreparingSilenceBoundSec"/> so existing callers stay non-breaking and a
    /// standalone consumer never interrupts a normal multi-minute manifest diff.
    /// </param>
    public TransportTimeoutPolicy(
        int readTimeoutMs,
        int keepAliveTimeSec,
        int keepAliveIntervalSec,
        int keepAliveRetryCount,
        int sslHandshakeWatchdogSec,
        int interMessageSilenceBoundSec,
        int preparingSilenceBoundSec = DefaultPreparingSilenceBoundSec)
    {
        if (readTimeoutMs != Timeout.Infinite && readTimeoutMs <= 0) {
            throw new ArgumentOutOfRangeException(nameof(readTimeoutMs), readTimeoutMs, "Read timeout must be positive or Timeout.Infinite.");
        }
        if (keepAliveTimeSec <= 0) {
            throw new ArgumentOutOfRangeException(nameof(keepAliveTimeSec), keepAliveTimeSec, "Keepalive time must be positive.");
        }
        if (keepAliveIntervalSec <= 0) {
            throw new ArgumentOutOfRangeException(nameof(keepAliveIntervalSec), keepAliveIntervalSec, "Keepalive interval must be positive.");
        }
        if (keepAliveRetryCount <= 0) {
            throw new ArgumentOutOfRangeException(nameof(keepAliveRetryCount), keepAliveRetryCount, "Keepalive retry count must be positive.");
        }
        if (sslHandshakeWatchdogSec <= 0) {
            throw new ArgumentOutOfRangeException(nameof(sslHandshakeWatchdogSec), sslHandshakeWatchdogSec, "SSL handshake watchdog bound must be positive.");
        }
        if (interMessageSilenceBoundSec <= 0) {
            throw new ArgumentOutOfRangeException(nameof(interMessageSilenceBoundSec), interMessageSilenceBoundSec, "Inter-message silence bound must be positive.");
        }
        if (preparingSilenceBoundSec <= 0) {
            throw new ArgumentOutOfRangeException(nameof(preparingSilenceBoundSec), preparingSilenceBoundSec, "Preparing silence bound must be positive.");
        }

        ReadTimeoutMs = readTimeoutMs;
        KeepAliveTimeSec = keepAliveTimeSec;
        KeepAliveIntervalSec = keepAliveIntervalSec;
        KeepAliveRetryCount = keepAliveRetryCount;
        SslHandshakeWatchdogSec = sslHandshakeWatchdogSec;
        InterMessageSilenceBoundSec = interMessageSilenceBoundSec;
        PreparingSilenceBoundSec = preparingSilenceBoundSec;
    }

    /// <summary>
    /// #2193: the library-default Preparing-phase silence bound in SECONDS (4 minutes). Generous enough
    /// that a legitimate large-device on-device manifest diff (observed at several minutes on heavy
    /// iPhone 16 Pro Max users, iOS 26.x) finishes uninterrupted, while still bounding a genuinely
    /// wedged Preparing window. Mirrors the host default
    /// <c>BackupConfiguration.UsbPreparingStallThresholdSec</c>; the host overrides it via
    /// <see cref="ForUsb(int, int, int)"/>.
    /// </summary>
    public const int DefaultPreparingSilenceBoundSec = 4 * 60;

    /// <summary>
    /// The SSL-handshake watchdog bound as a <see cref="TimeSpan"/> for direct use with a
    /// <see cref="CancellationTokenSource"/>.
    /// </summary>
    public TimeSpan SslHandshakeWatchdog => TimeSpan.FromSeconds(SslHandshakeWatchdogSec);

    /// <summary>
    /// The DlLoop inter-message silence bound (TIGHT, in-transfer) as a <see cref="TimeSpan"/>.
    /// </summary>
    public TimeSpan InterMessageSilenceBound => TimeSpan.FromSeconds(InterMessageSilenceBoundSec);

    /// <summary>
    /// #2193: the generous pre-first-file <c>Preparing</c>-phase silence bound as a <see cref="TimeSpan"/>.
    /// </summary>
    public TimeSpan PreparingSilenceBound => TimeSpan.FromSeconds(PreparingSilenceBoundSec);

    /// <summary>
    /// USB (usbmux) transport policy -- the reliability-critical, fail-fast-into-recovery path and the
    /// library default. Keepalive budget preserves the #1857 intent (~7 min:
    /// <c>120 + 10*30</c>, kept under the DeviceLinkService bulk-read timeout) while every OTHER bound
    /// is strictly tighter than <see cref="WiFiLoose"/>: a bounded (not infinite) SSL-handshake
    /// watchdog and a seconds-scale inter-message silence bound so a wedge is caught fast and fed into
    /// reconnect-and-resume. The bulk-read timeout mirrors the DeviceLinkService 10-minute budget so
    /// the read itself is unchanged; the fast-fail comes from the inter-message bound, not from
    /// shortening the read.
    /// </summary>
    public static TransportTimeoutPolicy UsbTight { get; } = new TransportTimeoutPolicy(
        readTimeoutMs: 10 * 60 * 1000,
        keepAliveTimeSec: 120,
        keepAliveIntervalSec: 30,
        keepAliveRetryCount: 10,
        sslHandshakeWatchdogSec: 60,
        interMessageSilenceBoundSec: 45,
        // #2193: the tight 45s inter-message bound governs ONLY the in-transfer phase; a healthy
        // Preparing diff is silent for minutes, so it uses the generous library-default Preparing bound.
        preparingSilenceBoundSec: DefaultPreparingSilenceBoundSec);

    /// <summary>
    /// WiFi (lockdown/TCP) transport policy -- LOOSE, preserving existing behavior. Every bound is
    /// >= the corresponding <see cref="UsbTight"/> bound: the SSL-handshake watchdog and the
    /// inter-message silence bound are generous so the fork adds NO WiFi resilience and makes NO
    /// gratuitous WiFi change (#1926 tight lockdown timeouts, #2081 finished-latch loop timing, #1999
    /// SSL handling all left intact). USB is the only transport this fork tightens.
    /// </summary>
    public static TransportTimeoutPolicy WiFiLoose { get; } = new TransportTimeoutPolicy(
        readTimeoutMs: 10 * 60 * 1000,
        keepAliveTimeSec: 120,
        keepAliveIntervalSec: 30,
        keepAliveRetryCount: 10,
        sslHandshakeWatchdogSec: 300,
        interMessageSilenceBoundSec: 10 * 60,
        // #2193: WiFi keeps a single loose bound — the Preparing bound matches its loose inter-message
        // bound so a WiFi Preparing window is never tightened. (The DlLoop applies the inter-message
        // bound only on USB anyway; this keeps the value object internally consistent.)
        preparingSilenceBoundSec: 10 * 60);

    /// <summary>
    /// ScribeHold fork (#2190): build the USB-tight policy the host drives from
    /// <c>BackupConfiguration</c>. Keeps the #1857 keepalive budget and the DeviceLinkService-matched
    /// bulk-read timeout from <see cref="UsbTight"/> (neither is a host-tunable key), and overrides ONLY
    /// the two config-driven bounds — the SSL-handshake watchdog and the DlLoop inter-message silence
    /// bound — so the Task-3 keys <c>SslHandshakeWatchdogSec</c> and <c>UsbInterMessageSilenceBoundSec</c>
    /// actually take effect on every USB connection instead of the hard-coded default.
    /// </summary>
    /// <param name="sslHandshakeWatchdogSec">SSL-handshake watchdog bound (seconds); from <c>BackupConfiguration.SslHandshakeWatchdogSec</c>.</param>
    /// <param name="interMessageSilenceBoundSec">DlLoop TIGHT in-transfer inter-message silence bound (seconds); from <c>BackupConfiguration.UsbInterMessageSilenceBoundSec</c>.</param>
    /// <param name="preparingSilenceBoundSec">
    /// #2193: the generous pre-first-file <c>Preparing</c>-phase silence bound (seconds); from
    /// <c>BackupConfiguration.UsbPreparingStallThresholdSec</c>. Defaults to
    /// <see cref="DefaultPreparingSilenceBoundSec"/> so a caller that has not adopted the third key
    /// keeps the safe generous library default.
    /// </param>
    public static TransportTimeoutPolicy ForUsb(
        int sslHandshakeWatchdogSec,
        int interMessageSilenceBoundSec,
        int preparingSilenceBoundSec = DefaultPreparingSilenceBoundSec)
    {
        return new TransportTimeoutPolicy(
            readTimeoutMs: UsbTight.ReadTimeoutMs,
            keepAliveTimeSec: UsbTight.KeepAliveTimeSec,
            keepAliveIntervalSec: UsbTight.KeepAliveIntervalSec,
            keepAliveRetryCount: UsbTight.KeepAliveRetryCount,
            sslHandshakeWatchdogSec: sslHandshakeWatchdogSec,
            interMessageSilenceBoundSec: interMessageSilenceBoundSec,
            preparingSilenceBoundSec: preparingSilenceBoundSec);
    }

    /// <summary>
    /// True when EVERY bound in this policy is strictly tighter than (or, for the keepalive budget that
    /// #1857 pins on both transports, equal to) <paramref name="other"/>. The transport-split invariant
    /// asserts <c>UsbTight.IsTighterThan(WiFiLoose)</c>: USB read-timeout/handshake-watchdog/
    /// inter-message bound are strictly &lt; WiFi's, with the keepalive budget preserved as the shared
    /// #1857 value.
    /// </summary>
    public bool IsTighterThan(TransportTimeoutPolicy other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return SslHandshakeWatchdogSec < other.SslHandshakeWatchdogSec
            && InterMessageSilenceBoundSec < other.InterMessageSilenceBoundSec
            && ReadTimeoutMs <= other.ReadTimeoutMs
            && KeepAliveBudgetSec <= other.KeepAliveBudgetSec;
    }
}
