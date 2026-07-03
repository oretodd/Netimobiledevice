using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for the #2197 (P0-D) version-exchange bound. The three pre-DlLoop version-exchange reads
/// (DLMessageVersionExchange, DLMessageDeviceReady, mb2 Hello response) used to go straight to the coarse
/// ~10-minute stream read: a RESUMED session hitting a busy-but-silent <c>backupd</c> waited the full 10
/// minutes and then dead-ended as a bare <see cref="TimeoutException"/> → fatal on attempt 1/3. The fix
/// bounds each read on USB and raises a dedicated, classifiable
/// <see cref="DeviceLinkVersionExchangeTimeoutException"/> that FEEDS reconnect-and-resume.
///
/// These pin the properties of the bounded signal and the transport-aware timing behavior of the bounded
/// read (the read function is injected — no live socket).
/// </summary>
[TestClass]
public class DeviceLinkVersionExchangeBoundTests
{
    private static readonly TimeSpan UsbBound = TimeSpan.FromSeconds(35);

    /// <summary>A read that never returns — models a busy-but-silent backupd on a resumed session.</summary>
    private static Func<CancellationToken, Task<ArrayNode>> NeverReturnsRead()
        => async ct => {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return [];
        };

    [TestMethod]
    [Description("#2197 (P0-D): the version-exchange timeout derives from TimeoutException (the host's inner " +
                 "catch(TimeoutException) ladder still captures it) and carries its bound.")]
    public void VersionExchangeTimeout_IsBoundedClassifiableSignal_DerivingFromTimeoutException()
    {
        DeviceLinkVersionExchangeTimeoutException ex = new(UsbBound);

        Assert.IsInstanceOfType<TimeoutException>(ex,
            "The version-exchange timeout MUST derive from TimeoutException so the host's inner " +
            "catch(TimeoutException) ladder still captures it (mirrors DeviceLinkInterMessageTimeoutException).");
        Assert.AreEqual(UsbBound, ex.Bound, "The signal carries the bound that was exceeded.");
        Assert.IsTrue(ex.Message.Contains("35", StringComparison.Ordinal),
            "The message names the bound in seconds for diagnostics.");
    }

    [TestMethod]
    [Description("#2197 (P0-D): the version-exchange timeout is a DISTINCT type from both the coarse stream " +
                 "TimeoutException and the inter-message timeout, so the coordinator can classify it precisely.")]
    public void VersionExchangeTimeout_IsDistinctType()
    {
        DeviceLinkVersionExchangeTimeoutException versionExchange = new(UsbBound);
        DeviceLinkInterMessageTimeoutException interMessage = new(UsbBound);
        TimeoutException plainStreamTimeout = new("Timeout waiting for message from service");

        Assert.IsNotInstanceOfType<DeviceLinkVersionExchangeTimeoutException>(interMessage,
            "The inter-message timeout must NOT be mistaken for the version-exchange timeout.");
        Assert.IsNotInstanceOfType<DeviceLinkVersionExchangeTimeoutException>(plainStreamTimeout,
            "A plain stream TimeoutException must NOT be the version-exchange timeout.");
        Assert.IsNotInstanceOfType<DeviceLinkInterMessageTimeoutException>(versionExchange,
            "The version-exchange timeout is its own type, not the inter-message timeout.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2197 (P0-D): a USB version-exchange silence trips the bound DETERMINISTICALLY in ~the bound, " +
                 "NOT at the 10-minute read timeout, and surfaces the dedicated signal.")]
    public async Task UsbSilence_TripsVersionExchangeBoundQuickly()
    {
        TimeSpan bound = TimeSpan.FromMilliseconds(200);
        Stopwatch sw = Stopwatch.StartNew();

        DeviceLinkVersionExchangeTimeoutException ex = await Assert.ThrowsExactlyAsync<DeviceLinkVersionExchangeTimeoutException>(
            () => DeviceLinkService.ReceiveWithVersionExchangeBoundAsync(
                isUsbTransport: true, bound, NeverReturnsRead(), NullLogger.Instance, CancellationToken.None),
            "A USB version-exchange silence must trip the version-exchange bound, not hang on the long read.");
        sw.Stop();

        Assert.AreEqual(bound, ex.Bound, "The raised signal carries the bound that tripped.");
        Assert.IsTrue(sw.Elapsed < TimeSpan.FromSeconds(4),
            $"The bound must trip in ~the bound (elapsed {sw.ElapsedMilliseconds}ms), far below the 10-minute read timeout.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2197 (P0-D): on WiFi the version-exchange bound is NOT applied — a silent read is not " +
                 "converted into a version-exchange timeout (WiFi behavior untouched).")]
    public async Task WiFiSilence_DoesNotTripVersionExchangeBound()
    {
        TimeSpan wouldBeBound = TimeSpan.FromMilliseconds(200);
        using CancellationTokenSource callerCts = new();

        Task<ArrayNode> pending = DeviceLinkService.ReceiveWithVersionExchangeBoundAsync(
            isUsbTransport: false, wouldBeBound, NeverReturnsRead(), NullLogger.Instance, callerCts.Token);

        await Task.Delay(500).ConfigureAwait(false);
        Assert.IsFalse(pending.IsCompleted,
            "On WiFi the read must still be pending (no version-exchange bound applied).");

        callerCts.Cancel();
        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(() => pending);
        Assert.IsNotInstanceOfType<DeviceLinkVersionExchangeTimeoutException>(ex,
            "A WiFi read is never converted into the bounded version-exchange transport-drop signal.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2197 (P0-D): a genuine CALLER cancellation is propagated, never reclassified as a " +
                 "version-exchange timeout.")]
    public async Task CallerCancellation_IsNotReclassified()
    {
        TimeSpan bound = TimeSpan.FromSeconds(30);
        using CancellationTokenSource callerCts = new();

        Task<ArrayNode> pending = DeviceLinkService.ReceiveWithVersionExchangeBoundAsync(
            isUsbTransport: true, bound, NeverReturnsRead(), NullLogger.Instance, callerCts.Token);
        callerCts.Cancel();

        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(() => pending);
        Assert.IsNotInstanceOfType<DeviceLinkVersionExchangeTimeoutException>(ex,
            "A caller cancellation must NOT be reclassified as the bounded version-exchange signal.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2197 (P0-D): a reply that arrives within the bound is returned unchanged.")]
    public async Task ReplyWithinBound_IsReturnedNormally()
    {
        TimeSpan bound = TimeSpan.FromSeconds(30);
        ArrayNode expected = [new StringNode("DLMessageVersionExchange"), new IntegerNode(400), new IntegerNode(0)];
        Func<CancellationToken, Task<ArrayNode>> read = _ => Task.FromResult(expected);

        ArrayNode actual = await DeviceLinkService.ReceiveWithVersionExchangeBoundAsync(
            isUsbTransport: true, bound, read, NullLogger.Instance, CancellationToken.None);

        Assert.AreSame(expected, actual, "A reply within the bound must be returned unchanged.");
    }
}
