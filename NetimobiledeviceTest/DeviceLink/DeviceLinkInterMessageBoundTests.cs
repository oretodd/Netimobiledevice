using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for the DlLoop inter-message silence bound (#2181).
///
/// Background: between mb2 messages, <c>DlLoop</c> historically waited on the coarse ~10-minute
/// <c>SERVICE_READ_TIMEOUT_MS</c> stream read. When a USB device went silent BETWEEN messages (the
/// wedge), the loop blocked for up to ten minutes before surfacing anything. The fix adds a USB-tight
/// inter-message silence bound (seconds): if the gap between messages exceeds it, a bounded,
/// classifiable <see cref="DeviceLinkInterMessageTimeoutException"/> is raised — a transport-drop
/// SIGNAL that FEEDS reconnect-and-resume — rather than a ten-minute hang. WiFi keeps its loose
/// behavior (no added bound).
///
/// These tests pin the pure gate (<see cref="DeviceLinkService.ShouldApplyInterMessageBound"/>) that
/// decides whether the bound applies, and the properties of the bounded transport-drop signal, without
/// a live socket.
/// </summary>
[TestClass]
public class DeviceLinkInterMessageBoundTests
{
    private static readonly TimeSpan TightUsbBound = TimeSpan.FromSeconds(30);

    [TestMethod]
    [Description("USB transport with a positive bound applies the inter-message silence bound.")]
    public void Usb_WithPositiveBound_AppliesBound()
    {
        Assert.IsTrue(
            DeviceLinkService.ShouldApplyInterMessageBound(isUsbTransport: true, bound: TightUsbBound),
            "On USB the tight inter-message bound must be applied so a between-message silence trips in seconds, feeding reconnect-and-resume.");
    }

    [TestMethod]
    [Description("WiFi transport does NOT apply the inter-message bound — loose WiFi loop timing is preserved.")]
    public void WiFi_DoesNotApplyBound()
    {
        Assert.IsFalse(
            DeviceLinkService.ShouldApplyInterMessageBound(isUsbTransport: false, bound: TightUsbBound),
            "WiFi keeps its loose behavior; the inter-message bound must never be applied on WiFi (no WiFi regression, no added WiFi resilience).");
    }

    [TestMethod]
    [Description("A non-positive bound disables the inter-message bound even on USB (a misconfigured host cannot wedge on a zero bound).")]
    public void Usb_WithNonPositiveBound_DoesNotApplyBound()
    {
        Assert.IsFalse(
            DeviceLinkService.ShouldApplyInterMessageBound(isUsbTransport: true, bound: TimeSpan.Zero),
            "A zero bound must fall back to the plain read path, not apply a 0-length (instantly-tripping) bound.");
        Assert.IsFalse(
            DeviceLinkService.ShouldApplyInterMessageBound(isUsbTransport: true, bound: TimeSpan.FromSeconds(-5)),
            "A negative bound must likewise be treated as disabled.");
    }

    [TestMethod]
    [Description("The bounded transport-drop signal derives from TimeoutException (existing generic timeout handling still catches it) and carries its bound.")]
    public void InterMessageTimeout_IsBoundedClassifiableSignal()
    {
        DeviceLinkInterMessageTimeoutException ex = new(TightUsbBound);

        Assert.IsInstanceOfType<TimeoutException>(ex,
            "The inter-message timeout must derive from TimeoutException so any existing generic timeout handling still catches it as a bounded (not terminal) condition.");
        Assert.AreEqual(TightUsbBound, ex.Bound,
            "The signal carries the bound that was exceeded so a consumer can log/classify it.");
        Assert.IsTrue(ex.Message.Contains("30", StringComparison.Ordinal),
            "The message names the bound in seconds for diagnostics.");
    }

    [TestMethod]
    [Description("The inter-message timeout is a DISTINCT type from the coarse stream TimeoutException, so a consumer can classify a between-message wedge as a transient transport drop.")]
    public void InterMessageTimeout_IsDistinctFromPlainTimeout()
    {
        DeviceLinkInterMessageTimeoutException interMessage = new(TightUsbBound);
        TimeoutException plainStreamTimeout = new("Timeout waiting for message from service");

        Assert.IsInstanceOfType<DeviceLinkInterMessageTimeoutException>(interMessage);
        Assert.IsNotInstanceOfType<DeviceLinkInterMessageTimeoutException>(plainStreamTimeout,
            "A plain stream TimeoutException must NOT be mistaken for the bounded inter-message drop signal — the dedicated type is what lets the coordinator route a between-message wedge into reconnect-and-resume.");
    }

    // ── End-to-end timing behavior (the read function is injected — no live socket) ─────────────

    /// <summary>A read that never returns — models a device that has gone silent between messages.</summary>
    private static Func<CancellationToken, Task<ArrayNode>> NeverReturnsRead()
        => async ct => {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return [];
        };

    [TestMethod]
    [Timeout(5000)]
    [Description("(b) A simulated mid-loop inter-message silence trips the USB bound DETERMINISTICALLY in ~the bound, NOT at the 10min read timeout.")]
    public async Task UsbSilence_TripsBoundQuickly_NotAtTenMinuteReadTimeout()
    {
        // A tight test bound stands in for the USB-tight production value; the device never replies.
        TimeSpan bound = TimeSpan.FromMilliseconds(200);
        Stopwatch sw = Stopwatch.StartNew();

        DeviceLinkInterMessageTimeoutException ex = await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
            () => DeviceLinkService.ReceiveWithInterMessageBoundAsync(
                isUsbTransport: true, bound, NeverReturnsRead(), NullLogger.Instance, CancellationToken.None),
            "A USB between-message silence must trip the inter-message bound, not hang on the long read.");
        sw.Stop();

        Assert.AreEqual(bound, ex.Bound, "The raised signal carries the bound that tripped.");
        // The whole point: it fires near the bound, in seconds — provably not the ~10-minute
        // SERVICE_READ_TIMEOUT_MS. A generous ceiling keeps the assertion deterministic on a loaded CI
        // box while still being three orders of magnitude below ten minutes.
        Assert.IsTrue(sw.Elapsed < TimeSpan.FromSeconds(4),
            $"The bound must trip in ~the bound (elapsed {sw.ElapsedMilliseconds}ms), far below the 10-minute read timeout.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("On WiFi, the bounded-read helper does NOT impose the bound — a silent read is NOT converted into an inter-message timeout (loose WiFi preserved).")]
    public async Task WiFiSilence_DoesNotTripInterMessageBound()
    {
        // WiFi + a silent read: the helper must defer to the plain read with no added bound. We prove
        // it does not raise the inter-message signal within a window that WOULD have tripped a USB
        // bound of the same length, then cancel to end the test.
        TimeSpan wouldBeBound = TimeSpan.FromMilliseconds(200);
        using CancellationTokenSource callerCts = new();

        Func<CancellationToken, Task<ArrayNode>> read = async ct => {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return [];
        };

        Task<ArrayNode> pending = DeviceLinkService.ReceiveWithInterMessageBoundAsync(
            isUsbTransport: false, wouldBeBound, read, NullLogger.Instance, callerCts.Token);

        // Wait well past the would-be bound; on WiFi nothing should have tripped.
        await Task.Delay(500).ConfigureAwait(false);
        Assert.IsFalse(pending.IsCompleted,
            "On WiFi the read must still be pending (no inter-message bound applied); it only ends on a real read or caller cancellation.");

        callerCts.Cancel();
        // TaskCanceledException derives from OperationCanceledException; assert the base type
        // (non-exactly) so the caller-cancellation classification is what matters, not the exact subtype.
        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(() => pending,
            "A WiFi read ends via the caller's own cancellation, never a synthetic inter-message timeout.");
        Assert.IsNotInstanceOfType<DeviceLinkInterMessageTimeoutException>(ex,
            "A WiFi read is never converted into the bounded inter-message transport-drop signal.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("A genuine CALLER cancellation is propagated as OperationCanceledException, never reclassified as an inter-message timeout.")]
    public async Task CallerCancellation_IsNotReclassifiedAsInterMessageTimeout()
    {
        TimeSpan bound = TimeSpan.FromSeconds(30); // large, so the bound does NOT fire during the test
        using CancellationTokenSource callerCts = new();

        Task<ArrayNode> pending = DeviceLinkService.ReceiveWithInterMessageBoundAsync(
            isUsbTransport: true, bound, NeverReturnsRead(), NullLogger.Instance, callerCts.Token);

        callerCts.Cancel();

        // TaskCanceledException : OperationCanceledException — assert the base type non-exactly.
        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(() => pending,
            "A caller-requested cancellation must surface as OperationCanceledException.");
        Assert.IsNotInstanceOfType<DeviceLinkInterMessageTimeoutException>(ex,
            "A caller cancellation must NOT be reclassified as the bounded inter-message transport-drop signal.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("When a message arrives within the bound, it is returned normally (the bound does not interfere with a responsive device).")]
    public async Task MessageArrivesWithinBound_IsReturnedNormally()
    {
        TimeSpan bound = TimeSpan.FromSeconds(30);
        ArrayNode expected = [new StringNode("DLMessageProcessMessage")];

        Func<CancellationToken, Task<ArrayNode>> read = _ => Task.FromResult(expected);

        ArrayNode actual = await DeviceLinkService.ReceiveWithInterMessageBoundAsync(
            isUsbTransport: true, bound, read, NullLogger.Instance, CancellationToken.None);

        Assert.AreSame(expected, actual, "A message that arrives within the bound must be returned unchanged.");
    }

    // ── #2190: the DlLoop bound is SEEDED from the connection's transport policy ───────────────────

    [TestMethod]
    [Description("#2190: DeviceLinkService seeds its inter-message silence bound from the connection's " +
                 "TransportTimeoutPolicy, so the host-configured UsbInterMessageSilenceBoundSec (carried " +
                 "on the ServiceConnection via LockdownClient.TimeoutPolicy) flows down without a separate " +
                 "SetUsbInterMessageSilenceBound call.")]
    public void Ctor_SeedsInterMessageBoundFromConnectionPolicy()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        // Host-configured policy: an inter-message bound distinct from the UsbTight default (45s).
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 17);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        TimeSpan seeded = ReadBoundField(dl);
        Assert.AreEqual(TimeSpan.FromSeconds(17), seeded,
            "The DlLoop inter-message bound must be seeded from the connection's policy so the host config value takes effect.");
    }

    [TestMethod]
    [Description("#2190: with the default (UsbTight) policy, the seeded bound is the USB-tight default — " +
                 "a standalone consumer that never overrides the policy still gets a safe bound.")]
    public void Ctor_DefaultPolicy_SeedsUsbTightBound()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        // No policy override → the ServiceConnection default is TransportTimeoutPolicy.UsbTight.

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        TimeSpan seeded = ReadBoundField(dl);
        Assert.AreEqual(TransportTimeoutPolicy.UsbTight.InterMessageSilenceBound, seeded,
            "With the default policy the seeded bound must equal the UsbTight inter-message bound.");
    }

    private static TimeSpan ReadBoundField(DeviceLinkService dl)
    {
        FieldInfo field = typeof(DeviceLinkService).GetField("_usbInterMessageSilenceBound",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("_usbInterMessageSilenceBound field must exist on DeviceLinkService.");
        return (TimeSpan)field.GetValue(dl)!;
    }

    // ── #2193: the Preparing phase uses a GENEROUS bound; the tight bound governs ONLY in-transfer ──

    private static readonly TimeSpan GenerousPreparingBound = TimeSpan.FromMinutes(4);

    [TestMethod]
    [Description("#2193: BEFORE the first real file transfer (Preparing window), the DlLoop selects the " +
                 "GENEROUS Preparing bound — a healthy multi-minute manifest diff must not be interrupted.")]
    public void SelectInterMessageBound_PreTransfer_UsesGenerousPreparingBound()
    {
        TimeSpan selected = DeviceLinkService.SelectInterMessageBound(
            realTransferStarted: false, preparingBound: GenerousPreparingBound, inTransferBound: TightUsbBound);

        Assert.AreEqual(GenerousPreparingBound, selected,
            "Pre-first-file the device is building its on-device diff and is legitimately silent for minutes; " +
            "the generous Preparing bound must apply so the diff runs uninterrupted (the toddfone regression).");
    }

    [TestMethod]
    [Description("#2193: ONCE real transfer has started, the DlLoop selects the TIGHT in-transfer bound — " +
                 "a between-message gap is now genuinely anomalous and must be caught in seconds.")]
    public void SelectInterMessageBound_PostTransfer_UsesTightInTransferBound()
    {
        TimeSpan selected = DeviceLinkService.SelectInterMessageBound(
            realTransferStarted: true, preparingBound: GenerousPreparingBound, inTransferBound: TightUsbBound);

        Assert.AreEqual(TightUsbBound, selected,
            "Post-first-file a real mid-transfer stall must still be caught on the tight bound and fed into " +
            "reconnect-and-resume (the genuinely-good epic behavior is preserved).");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2193 (AC5): a Preparing-phase silence WITHIN the generous bound does NOT trip a reconnect — " +
                 "the diff is allowed to run. A tight in-transfer bound of the same length WOULD have tripped.")]
    public async Task PreparingSilence_WithinGenerousBound_DoesNotTrip()
    {
        // Model the Preparing window: real transfer has NOT started, so the generous bound applies. A
        // silence of ~90s–2min (here scaled down) sits well inside a generous bound but far past a tight one.
        TimeSpan generousBound = TimeSpan.FromMilliseconds(600);
        TimeSpan tightBound = TimeSpan.FromMilliseconds(150);
        TimeSpan preparingSelected = DeviceLinkService.SelectInterMessageBound(
            realTransferStarted: false, preparingBound: generousBound, inTransferBound: tightBound);

        using CancellationTokenSource callerCts = new();
        Task<ArrayNode> pending = DeviceLinkService.ReceiveWithInterMessageBoundAsync(
            isUsbTransport: true, preparingSelected, NeverReturnsRead(), NullLogger.Instance, callerCts.Token);

        // Wait past the TIGHT bound but within the generous one: nothing should have tripped.
        await Task.Delay(300).ConfigureAwait(false);
        Assert.IsFalse(pending.IsCompleted,
            "A Preparing silence within the generous bound must NOT trip an inter-message timeout — a tight " +
            "bound of the same length would have fired by now, manufacturing the toddfone failure.");

        callerCts.Cancel();
        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(() => pending);
        Assert.IsNotInstanceOfType<DeviceLinkInterMessageTimeoutException>(ex,
            "Within the generous Preparing bound the read ends only on caller cancellation, never a synthetic timeout.");
    }

    [TestMethod]
    [Timeout(5000)]
    [Description("#2193 (AC5): a Preparing silence BEYOND the generous bound DOES trip a bounded reconnect signal " +
                 "(the generous bound is a last-resort safety net, not disabled).")]
    public async Task PreparingSilence_BeyondGenerousBound_Trips()
    {
        TimeSpan generousBound = TimeSpan.FromMilliseconds(200);
        TimeSpan preparingSelected = DeviceLinkService.SelectInterMessageBound(
            realTransferStarted: false, preparingBound: generousBound, inTransferBound: TightUsbBound);

        DeviceLinkInterMessageTimeoutException ex = await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
            () => DeviceLinkService.ReceiveWithInterMessageBoundAsync(
                isUsbTransport: true, preparingSelected, NeverReturnsRead(), NullLogger.Instance, CancellationToken.None),
            "A Preparing silence that exceeds the GENEROUS bound must still surface the bounded transport-drop signal " +
            "so a genuinely wedged Preparing window is recovered — the safety net is raised, not removed.");

        Assert.AreEqual(generousBound, ex.Bound, "The raised signal carries the generous Preparing bound that tripped.");
    }

    [TestMethod]
    [Description("#2193: DeviceLinkService seeds its Preparing-phase bound from the connection's " +
                 "TransportTimeoutPolicy so the host-configured UsbPreparingStallThresholdSec takes effect.")]
    public void Ctor_SeedsPreparingBoundFromConnectionPolicy()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        // Host-configured policy: a Preparing bound distinct from both defaults.
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, preparingSilenceBoundSec: 200);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        TimeSpan seeded = ReadPreparingBoundField(dl);
        Assert.AreEqual(TimeSpan.FromSeconds(200), seeded,
            "The Preparing-phase bound must be seeded from the connection's policy so the host config value takes effect.");
    }

    [TestMethod]
    [Description("#2193: with the default (UsbTight) policy, the seeded Preparing bound is the generous library " +
                 "default (4 min) — a standalone consumer never interrupts a normal manifest diff.")]
    public void Ctor_DefaultPolicy_SeedsGenerousPreparingBound()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        TimeSpan seeded = ReadPreparingBoundField(dl);
        Assert.AreEqual(TransportTimeoutPolicy.UsbTight.PreparingSilenceBound, seeded,
            "With the default policy the seeded Preparing bound must equal the generous UsbTight Preparing bound.");
        Assert.IsTrue(seeded > TransportTimeoutPolicy.UsbTight.InterMessageSilenceBound,
            "The Preparing bound must be strictly GENEROUS relative to the tight in-transfer bound.");
    }

    private static TimeSpan ReadPreparingBoundField(DeviceLinkService dl)
    {
        FieldInfo field = typeof(DeviceLinkService).GetField("_usbPreparingSilenceBound",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("_usbPreparingSilenceBound field must exist on DeviceLinkService.");
        return (TimeSpan)field.GetValue(dl)!;
    }

    private static ServiceConnection CreateServiceConnection(Socket connectedSocket, int timeout)
    {
        ConstructorInfo ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(Netimobiledevice.Usbmuxd.UsbmuxdDevice)],
            modifiers: null)
            ?? throw new AssertFailedException(
                "ServiceConnection(Socket, int, ILogger, UsbmuxdDevice?) constructor must exist for this test.");

        return (ServiceConnection)ctor.Invoke(
            [connectedSocket, timeout, NullLogger.Instance, null]);
    }

    /// <summary>A connected loopback TCP socket pair (client + accepted server), disposed together.</summary>
    private sealed class SocketPair : IDisposable
    {
        public required Socket Client { get; init; }
        public required Socket Server { get; init; }

        public static SocketPair CreateConnected()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            Task<Socket> acceptTask = listener.AcceptSocketAsync();

            var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
            client.Connect(IPAddress.Loopback, port);
            Socket server = acceptTask.GetAwaiter().GetResult();

            return new SocketPair { Client = client, Server = server };
        }

        public void Dispose()
        {
            try { Client.Dispose(); } catch (SocketException) { }
            try { Server.Dispose(); } catch (SocketException) { }
        }
    }
}
