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

    private static TransportTimeoutPolicy Build(
        int readTimeoutMs = 600_000,
        int keepAliveTimeSec = 120,
        int keepAliveIntervalSec = 30,
        int keepAliveRetryCount = 10,
        int sslHandshakeWatchdogSec = 60,
        int interMessageSilenceBoundSec = 45)
    {
        return new TransportTimeoutPolicy(
            readTimeoutMs,
            keepAliveTimeSec,
            keepAliveIntervalSec,
            keepAliveRetryCount,
            sslHandshakeWatchdogSec,
            interMessageSilenceBoundSec);
    }
}
