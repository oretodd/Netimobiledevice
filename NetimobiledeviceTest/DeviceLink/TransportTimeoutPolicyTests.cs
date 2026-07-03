using Netimobiledevice.DeviceLink;
using System;
using System.Threading;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// #2182: the named <see cref="TransportTimeoutPolicy"/> is the single source of truth for every
/// transport-sensitive bound (read timeout, keepalive budget, SSL-handshake watchdog, DlLoop
/// inter-message silence bound). These tests prove the transport-split invariant — USB selects
/// STRICTLY TIGHTER values than WiFi — and that the value object validates its inputs and defaults to
/// USB-tight so a standalone submodule consumer is safe.
/// </summary>
[TestClass]
public class TransportTimeoutPolicyTests
{
    [TestMethod]
    [Description("Transport-split invariant (#2182): USB is tighter than WiFi. The SSL-handshake " +
                 "watchdog and the inter-message silence bound are STRICTLY smaller on USB; the " +
                 "read-timeout and #1857 keepalive budget are <= WiFi (the keepalive budget is the " +
                 "shared #1857 value on both transports).")]
    public void UsbTight_IsStrictlyTighterThan_WiFiLoose()
    {
        TransportTimeoutPolicy usb = TransportTimeoutPolicy.UsbTight;
        TransportTimeoutPolicy wifi = TransportTimeoutPolicy.WiFiLoose;

        Assert.IsTrue(usb.IsTighterThan(wifi),
            "UsbTight must report itself tighter than WiFiLoose (transport-split invariant).");

        Assert.IsTrue(usb.SslHandshakeWatchdogSec < wifi.SslHandshakeWatchdogSec,
            "USB SSL-handshake watchdog must be strictly tighter than WiFi's.");
        Assert.IsTrue(usb.InterMessageSilenceBoundSec < wifi.InterMessageSilenceBoundSec,
            "USB inter-message silence bound must be strictly tighter than WiFi's.");
        Assert.IsTrue(usb.ReadTimeoutMs <= wifi.ReadTimeoutMs,
            "USB read-timeout must not exceed WiFi's.");
        Assert.IsFalse(wifi.IsTighterThan(usb),
            "WiFiLoose must NOT report itself tighter than UsbTight.");
    }

    [TestMethod]
    [Description("#2182: the USB-tight SSL-handshake watchdog is ~60s — bounded (not Timeout.Infinite) " +
                 "so a lost close_notify cannot hang, yet generous enough not to clip a legitimate " +
                 "trust/passcode dialog (#1999 intent).")]
    public void UsbTight_SslHandshakeWatchdog_IsAboutSixtySeconds()
    {
        Assert.AreEqual(60, TransportTimeoutPolicy.UsbTight.SslHandshakeWatchdogSec);
        Assert.AreEqual(TimeSpan.FromSeconds(60), TransportTimeoutPolicy.UsbTight.SslHandshakeWatchdog);
    }

    [TestMethod]
    [Description("#2182/#1857: the USB keepalive budget preserves the ~7-minute #1857 intent " +
                 "(120 + 10*30 = 420s), kept under the DeviceLinkService 10-minute read timeout.")]
    public void UsbTight_KeepAliveBudget_PreservesThe1857Intent()
    {
        TransportTimeoutPolicy usb = TransportTimeoutPolicy.UsbTight;

        Assert.AreEqual(120, usb.KeepAliveTimeSec);
        Assert.AreEqual(30, usb.KeepAliveIntervalSec);
        Assert.AreEqual(10, usb.KeepAliveRetryCount);
        Assert.AreEqual(420, usb.KeepAliveBudgetSec, "Budget = 120 + 10*30 = 420s (#1857).");
        Assert.IsTrue(usb.KeepAliveBudgetSec < usb.ReadTimeoutMs / 1000,
            "The keepalive budget must stay under the bulk-read timeout (#1857).");
    }

    [TestMethod]
    [Description("#2182: the inter-message silence bound (consumed by Task 1's DlLoop) is a small, " +
                 "seconds-scale value on USB so a between-message wedge is caught fast and feeds " +
                 "reconnect, rather than waiting out the 10-minute bulk read.")]
    public void UsbTight_InterMessageSilenceBound_IsSecondsScale_NotTheReadTimeout()
    {
        TransportTimeoutPolicy usb = TransportTimeoutPolicy.UsbTight;

        Assert.IsTrue(usb.InterMessageSilenceBoundSec > 0);
        Assert.IsTrue(usb.InterMessageSilenceBoundSec < usb.ReadTimeoutMs / 1000,
            "The inter-message bound must be far tighter than the bulk-read timeout so a wedge fails fast.");
        Assert.AreEqual(TimeSpan.FromSeconds(usb.InterMessageSilenceBoundSec), usb.InterMessageSilenceBound);
    }

    [TestMethod]
    [Description("#2182: a policy accepts Timeout.Infinite as a read timeout (for callers that manage " +
                 "the read budget themselves) but rejects a non-positive finite read timeout.")]
    public void Constructor_AcceptsInfiniteReadTimeout_RejectsNonPositiveFinite()
    {
        TransportTimeoutPolicy infinite = new TransportTimeoutPolicy(
            readTimeoutMs: Timeout.Infinite,
            keepAliveTimeSec: 120,
            keepAliveIntervalSec: 30,
            keepAliveRetryCount: 10,
            sslHandshakeWatchdogSec: 60,
            interMessageSilenceBoundSec: 45);
        Assert.AreEqual(Timeout.Infinite, infinite.ReadTimeoutMs);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new TransportTimeoutPolicy(
            readTimeoutMs: 0,
            keepAliveTimeSec: 120,
            keepAliveIntervalSec: 30,
            keepAliveRetryCount: 10,
            sslHandshakeWatchdogSec: 60,
            interMessageSilenceBoundSec: 45));
    }

    [TestMethod]
    [Description("#2182: the constructor rejects non-positive keepalive/watchdog/inter-message values " +
                 "so a mis-configured policy cannot silently disable a bound.")]
    public void Constructor_RejectsNonPositiveBounds()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(sslHandshakeWatchdogSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(interMessageSilenceBoundSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(keepAliveTimeSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(keepAliveIntervalSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(keepAliveRetryCount: 0));
    }

    [TestMethod]
    [Description("#2182: IsTighterThan(null) throws — a policy comparison needs a real peer.")]
    public void IsTighterThan_Null_Throws()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => TransportTimeoutPolicy.UsbTight.IsTighterThan(null!));
    }

    [TestMethod]
    [Description("#2190: ForUsb overrides ONLY the two config-driven bounds (SSL-handshake watchdog + " +
                 "inter-message silence) and keeps the #1857 keepalive budget and bulk-read timeout from " +
                 "UsbTight, so the host's BackupConfiguration values flow down without disturbing the " +
                 "non-tunable bounds.")]
    public void ForUsb_OverridesConfigDrivenBounds_KeepsUsbTightRest()
    {
        TransportTimeoutPolicy policy = TransportTimeoutPolicy.ForUsb(sslHandshakeWatchdogSec: 42, interMessageSilenceBoundSec: 17);

        Assert.AreEqual(42, policy.SslHandshakeWatchdogSec, "The SSL-handshake watchdog must come from the host config.");
        Assert.AreEqual(17, policy.InterMessageSilenceBoundSec, "The inter-message silence bound must come from the host config.");
        Assert.AreEqual(TransportTimeoutPolicy.UsbTight.ReadTimeoutMs, policy.ReadTimeoutMs, "The bulk-read timeout is not host-tunable; it stays at the UsbTight value.");
        Assert.AreEqual(TransportTimeoutPolicy.UsbTight.KeepAliveBudgetSec, policy.KeepAliveBudgetSec, "The #1857 keepalive budget is not host-tunable; it stays at the UsbTight value.");
    }

    [TestMethod]
    [Description("#2190: ForUsb still validates its bounds — a non-positive config value is rejected " +
                 "rather than silently disabling a bound.")]
    public void ForUsb_RejectsNonPositiveConfigValues()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TransportTimeoutPolicy.ForUsb(sslHandshakeWatchdogSec: 0, interMessageSilenceBoundSec: 17));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TransportTimeoutPolicy.ForUsb(sslHandshakeWatchdogSec: 42, interMessageSilenceBoundSec: 0));
    }

    // ── #2193: the generous pre-first-file Preparing-phase silence bound ────────────────────────────

    [TestMethod]
    [Description("#2193: the library-default Preparing bound (4 min) is GENEROUS relative to the tight " +
                 "in-transfer bound on both the UsbTight and WiFiLoose policies, so a normal multi-minute " +
                 "on-device manifest diff finishes uninterrupted.")]
    public void PreparingBound_IsGenerousRelativeToInterMessageBound()
    {
        // Read the const through the instance property (UsbTight defaults to it) so the assertion is a
        // real runtime check, not a compile-time-constant compare the analyzer would fold to always-true.
        Assert.AreEqual(4 * 60, TransportTimeoutPolicy.UsbTight.PreparingSilenceBoundSec,
            "The library-default Preparing bound (carried by UsbTight) is 4 minutes.");
        Assert.AreEqual(TransportTimeoutPolicy.DefaultPreparingSilenceBoundSec,
            TransportTimeoutPolicy.UsbTight.PreparingSilenceBoundSec,
            "UsbTight keeps the generous library-default Preparing bound (the tight 45s governs only in-transfer).");
        Assert.IsTrue(
            TransportTimeoutPolicy.UsbTight.PreparingSilenceBoundSec > TransportTimeoutPolicy.UsbTight.InterMessageSilenceBoundSec,
            "The Preparing bound must be strictly greater than the tight in-transfer bound on USB.");
        Assert.AreEqual(TimeSpan.FromSeconds(TransportTimeoutPolicy.UsbTight.PreparingSilenceBoundSec),
            TransportTimeoutPolicy.UsbTight.PreparingSilenceBound,
            "The TimeSpan accessor matches the seconds value.");
    }

    [TestMethod]
    [Description("#2193: ForUsb overrides the Preparing bound from the host config " +
                 "(BackupConfiguration.UsbPreparingStallThresholdSec) alongside the other two config-driven bounds.")]
    public void ForUsb_OverridesPreparingBound_FromHostConfig()
    {
        TransportTimeoutPolicy policy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 42, interMessageSilenceBoundSec: 17, preparingSilenceBoundSec: 240);

        Assert.AreEqual(240, policy.PreparingSilenceBoundSec, "The Preparing bound must come from the host config value.");
        Assert.AreEqual(17, policy.InterMessageSilenceBoundSec, "The tight in-transfer bound is unchanged.");
    }

    [TestMethod]
    [Description("#2193: ForUsb without the third arg keeps the generous library-default Preparing bound — " +
                 "a caller that has not adopted the new key is never regressed into interrupting a normal diff.")]
    public void ForUsb_WithoutPreparingArg_KeepsGenerousDefault()
    {
        TransportTimeoutPolicy policy = TransportTimeoutPolicy.ForUsb(sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30);

        Assert.AreEqual(TransportTimeoutPolicy.DefaultPreparingSilenceBoundSec, policy.PreparingSilenceBoundSec,
            "Omitting the Preparing arg must fall back to the generous library default, not a tight value.");
    }

    [TestMethod]
    [Description("#2193: the constructor rejects a non-positive Preparing bound so a mis-configured policy " +
                 "cannot disable the Preparing safety net.")]
    public void Constructor_RejectsNonPositivePreparingBound()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(preparingSilenceBoundSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(preparingSilenceBoundSec: -5));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, preparingSilenceBoundSec: 0));
    }

    // ── #2197 (P0-D/P0-B): the version-exchange bound and the Preparing hard cap ────────────────────

    [TestMethod]
    [Description("#2197 (P0-D): the USB-tight version-exchange bound is a tight seconds-scale value (35s) " +
                 "— far below the coarse ~10-minute stream read a busy backupd used to wedge on — while " +
                 "WiFi keeps a loose bound so its behavior is untouched.")]
    public void VersionExchangeBound_UsbTight_WiFiLoose()
    {
        TransportTimeoutPolicy usb = TransportTimeoutPolicy.UsbTight;
        TransportTimeoutPolicy wifi = TransportTimeoutPolicy.WiFiLoose;

        Assert.AreEqual(TransportTimeoutPolicy.DefaultVersionExchangeBoundSec, usb.VersionExchangeBoundSec);
        Assert.AreEqual(35, usb.VersionExchangeBoundSec, "The USB version-exchange bound is ~35s.");
        Assert.IsTrue(usb.VersionExchangeBoundSec < usb.ReadTimeoutMs / 1000,
            "The version-exchange bound must be far tighter than the bulk-read timeout so a busy backupd feeds reconnect fast.");
        Assert.IsTrue(usb.VersionExchangeBoundSec < wifi.VersionExchangeBoundSec,
            "USB must be strictly tighter than WiFi's loose version-exchange bound.");
        Assert.AreEqual(TimeSpan.FromSeconds(usb.VersionExchangeBoundSec), usb.VersionExchangeBound,
            "The TimeSpan accessor matches the seconds value.");
    }

    [TestMethod]
    [Description("#2197 (P0-B): the USB Preparing hard cap floors at 15 min and the library default (20 min) " +
                 "sits comfortably above a real on-device manifest diff, and is >= the generous Preparing bound.")]
    public void PreparingHardCap_UsbTight_IsGenerousAndAboveTheFloor()
    {
        TransportTimeoutPolicy usb = TransportTimeoutPolicy.UsbTight;

        Assert.AreEqual(TransportTimeoutPolicy.DefaultPreparingHardCapSec, usb.PreparingHardCapSec);
        Assert.AreEqual(20 * 60, usb.PreparingHardCapSec, "The library-default Preparing hard cap is 20 minutes.");
        Assert.IsTrue(usb.PreparingHardCapSec >= 15 * 60, "The Preparing hard cap must floor at 15 minutes.");
        Assert.IsTrue(usb.PreparingHardCapSec >= usb.PreparingSilenceBoundSec,
            "The hard cap must be >= the generous Preparing silence bound (a single probe interval).");
        Assert.AreEqual(TimeSpan.FromSeconds(usb.PreparingHardCapSec), usb.PreparingHardCap,
            "The TimeSpan accessor matches the seconds value.");
    }

    [TestMethod]
    [Description("#2197: ForUsb overrides the version-exchange bound and the Preparing hard cap from the " +
                 "host config alongside the existing bounds; omitting them keeps the library defaults.")]
    public void ForUsb_OverridesVersionExchangeAndHardCap_FromHostConfig()
    {
        TransportTimeoutPolicy overridden = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, preparingSilenceBoundSec: 240,
            versionExchangeBoundSec: 45, preparingHardCapSec: 1200);
        Assert.AreEqual(45, overridden.VersionExchangeBoundSec, "The version-exchange bound must come from the host config.");
        Assert.AreEqual(1200, overridden.PreparingHardCapSec, "The Preparing hard cap must come from the host config.");

        TransportTimeoutPolicy defaults = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30);
        Assert.AreEqual(TransportTimeoutPolicy.DefaultVersionExchangeBoundSec, defaults.VersionExchangeBoundSec,
            "Omitting the version-exchange arg keeps the tight library default.");
        Assert.AreEqual(TransportTimeoutPolicy.DefaultPreparingHardCapSec, defaults.PreparingHardCapSec,
            "Omitting the hard-cap arg keeps the generous library default.");
    }

    [TestMethod]
    [Description("#2197: the constructor rejects a non-positive version-exchange bound, and rejects a " +
                 "Preparing hard cap that is tighter than the generous Preparing bound (the cap can never " +
                 "be smaller than a single probe interval).")]
    public void Constructor_RejectsInvalidNewBounds()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(versionExchangeBoundSec: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(versionExchangeBoundSec: -5));
        // Hard cap < Preparing bound is rejected.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Build(preparingSilenceBoundSec: 240, preparingHardCapSec: 100));
        // Equal is allowed (a single-interval cap).
        TransportTimeoutPolicy equal = Build(preparingSilenceBoundSec: 240, preparingHardCapSec: 240);
        Assert.AreEqual(240, equal.PreparingHardCapSec);
    }

    private static TransportTimeoutPolicy Build(
        int readTimeoutMs = 600_000,
        int keepAliveTimeSec = 120,
        int keepAliveIntervalSec = 30,
        int keepAliveRetryCount = 10,
        int sslHandshakeWatchdogSec = 60,
        int interMessageSilenceBoundSec = 45,
        int preparingSilenceBoundSec = 240,
        int versionExchangeBoundSec = 35,
        int preparingHardCapSec = 1200)
    {
        return new TransportTimeoutPolicy(
            readTimeoutMs,
            keepAliveTimeSec,
            keepAliveIntervalSec,
            keepAliveRetryCount,
            sslHandshakeWatchdogSec,
            interMessageSilenceBoundSec,
            preparingSilenceBoundSec,
            versionExchangeBoundSec,
            preparingHardCapSec);
    }
}
