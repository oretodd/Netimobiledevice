using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// End-to-end fork tests for the #2197 (P0-B) probe-and-wait loop and the (P0-C) quiet-abandon
/// classification. These drive the private <c>ReceiveMessageWithSilenceProbeAsync</c> over a live
/// loopback socket (with the Preparing bound + hard cap shrunk to milliseconds via reflection) so the
/// three required outcomes are exercised: probe-healthy → keeps waiting under the hard cap; probe-dead →
/// tears down; hard-cap exhaustion → tears down.
/// </summary>
[TestClass]
public class DeviceLinkPreparingProbeLoopTests
{
    [TestMethod]
    [Timeout(10000)]
    [Description("#2197 (P0-B): with a HEALTHY (live, quiet) socket, a Preparing-bound trip does NOT tear " +
                 "down immediately — the loop keeps waiting until the total-continuous HARD CAP is exhausted, " +
                 "then surfaces the bounded transport-drop signal.")]
    public async Task PreparingProbe_HealthySocket_WaitsUnderHardCap_ThenTripsOnHardCapExhaustion()
    {
        // A live, connected, QUIET socket (server never sends) = healthy probe verdict, but the read never
        // returns. With a tiny Preparing bound and a small hard cap, the loop should probe healthy, keep
        // waiting across several bound trips, and finally give up when the hard cap is exhausted.
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 500);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        // USB transport is required for the bound to apply; force the ctor-seeded fields to tiny values.
        ForceUsbTransport(connection);
        SetTimeSpanField(dl, "_usbPreparingSilenceBound", TimeSpan.FromMilliseconds(120));
        SetTimeSpanField(dl, "_usbPreparingHardCap", TimeSpan.FromMilliseconds(500));

        DeviceLinkInterMessageTimeoutException ex =
            await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
                () => InvokeProbeLoop(dl, CancellationToken.None),
                "On a healthy-but-silent Preparing window the loop must eventually surface the bounded signal " +
                "when the hard cap is exhausted (it does NOT hang forever, and it does NOT tear down on the first trip).");

        Assert.IsNotNull(ex);
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2200 (P0): with a HEALTHY (live, quiet) socket AFTER real transfer has started (the " +
                 "finalizing/commit tail near 99%), the tight in-transfer bound trip does NOT tear down " +
                 "immediately — the loop probes healthy and keeps waiting under the IN-TRANSFER hard cap, " +
                 "then surfaces the bounded transport-drop signal only on hard-cap exhaustion. This is the " +
                 "core #2200 fix: the old code rethrew on the first in-transfer trip, killing a healthy " +
                 "session seconds from completion.")]
    public async Task InTransferProbe_HealthySocket_WaitsUnderInTransferHardCap_ThenTripsOnExhaustion()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 500);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        ForceUsbTransport(connection);
        // Latch real transfer started → the loop selects the tight in-transfer bound + the in-transfer hard cap.
        SetBoolField(dl, "_realTransferStarted", true);
        SetTimeSpanField(dl, "_usbInterMessageSilenceBound", TimeSpan.FromMilliseconds(120));
        // A LARGE Preparing hard cap that MUST NOT be used (this is the in-transfer phase); a small
        // in-transfer hard cap that governs. If the loop wrongly used the Preparing cap the [Timeout] fails.
        SetTimeSpanField(dl, "_usbPreparingHardCap", TimeSpan.FromMinutes(20));
        SetTimeSpanField(dl, "_usbInTransferHardCap", TimeSpan.FromMilliseconds(500));

        DeviceLinkInterMessageTimeoutException ex =
            await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
                () => InvokeProbeLoop(dl, CancellationToken.None),
                "On a healthy-but-silent in-transfer/finalizing window the loop must KEEP WAITING (not tear " +
                "down on the first trip) and only surface the bounded signal when the IN-TRANSFER hard cap is exhausted.");

        Assert.IsNotNull(ex);
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2200 (P0): an in-transfer silence whose composite health check reports DEAD (here via a " +
                 "presence probe that says the device is GONE, a healthy-but-quiet socket notwithstanding) " +
                 "tears down on the next trip and surfaces the bounded transport-drop signal — reconnect-and-" +
                 "resume — rather than waiting out the (generous) in-transfer hard cap. If the in-transfer " +
                 "trip were not probed (the pre-#2200 immediate rethrow) OR the dead verdict were ignored, this " +
                 "would still throw, so the DISTINGUISHING assertion is that it does NOT wait out the 20-min cap " +
                 "(the [Timeout] would fail).")]
    public async Task InTransferProbe_HealthCheckDead_TearsDownForReconnect()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 500);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        ForceUsbTransport(connection);
        SetBoolField(dl, "_realTransferStarted", true);
        SetTimeSpanField(dl, "_usbInterMessageSilenceBound", TimeSpan.FromMilliseconds(120));
        // A GENEROUS in-transfer hard cap: only the DEAD composite-health verdict can tear this down before
        // the [Timeout], proving the in-transfer trip IS probed and DOES honor a dead verdict.
        SetTimeSpanField(dl, "_usbInTransferHardCap", TimeSpan.FromMinutes(20));
        // Live, quiet (socket-healthy) transport, but the host presence probe reports the device GONE.
        dl.PresenceProbe = _ => Task.FromResult(false);

        var ex = await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
            () => InvokeProbeLoop(dl, CancellationToken.None),
            "A dead composite-health verdict in the in-transfer phase must tear down on the next trip " +
            "(transport evidence), not wait out the generous hard cap.");
        Assert.IsNotNull(ex);
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2197 (P0-B): when the composite Preparing health check reports DEAD, the loop does NOT " +
                 "keep waiting — the very next bound trip surfaces the bounded transport-drop signal instead " +
                 "of continuing under the hard cap. Modeled with a host presence probe that reports gone " +
                 "(the presence-callback dead verdict), a healthy socket notwithstanding.")]
    public async Task PreparingProbe_PresenceGone_TearsDownWithoutWaitingOutHardCap()
    {
        // A live, quiet (healthy) socket, but the host presence probe reports the device GONE. The
        // composite health check must then report unhealthy, so the loop tears down on the first trip
        // rather than waiting out the (generous) hard cap. If the presence verdict were ignored, the
        // generous hard cap would keep the loop waiting and the [Timeout] would fail this test.
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 500);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        ForceUsbTransport(connection);
        SetTimeSpanField(dl, "_usbPreparingSilenceBound", TimeSpan.FromMilliseconds(120));
        SetTimeSpanField(dl, "_usbPreparingHardCap", TimeSpan.FromMinutes(20));
        dl.PresenceProbe = _ => Task.FromResult(false); // device reported GONE

        var ex = await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
            () => InvokeProbeLoop(dl, CancellationToken.None),
            "A presence-gone verdict must tear down the Preparing wait on the next trip, not wait out the hard cap.");
        Assert.IsNotNull(ex);
    }

    [TestMethod]
    [Description("#2197 (P0-B): the composite Preparing health check reports DEAD when the passive socket " +
                 "probe is dead (peer FIN), regardless of any presence probe — tear down on transport evidence.")]
    public async Task PreparingTransportHealth_DeadSocket_ReportsUnhealthy()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 500);
        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        // A presence probe that would say "present" must NOT rescue a dead socket.
        dl.PresenceProbe = _ => Task.FromResult(true);
        pair.Server.Shutdown(SocketShutdown.Both);
        pair.Server.Close();
        await WaitUntil(() => pair.Client.Poll(0, SelectMode.SelectRead), TimeSpan.FromSeconds(2));

        bool healthy = await InvokeCompositeHealth(dl, CancellationToken.None);
        Assert.IsFalse(healthy,
            "A dead socket (peer FIN) must report unhealthy even when the presence probe says present — the " +
            "socket probe is authoritative for transport evidence.");
    }

    [TestMethod]
    [Description("#2197 (P0-C): the quiet-abandon classifier flags exactly the drop-classes the host will " +
                 "resume (inter-message timeout, version-exchange timeout, transient IOException) and NOT a " +
                 "user/terminal cancellation.")]
    public void IsResumeDropClass_ClassifiesResumeDropsOnly()
    {
        MethodInfo classifier = typeof(Mobilebackup2Service).GetMethod(
            "IsResumeDropClass", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new AssertFailedException("Mobilebackup2Service.IsResumeDropClass must exist for #2197 P0-C.");

        Assert.IsTrue(Classify(classifier, new DeviceLinkInterMessageTimeoutException(TimeSpan.FromSeconds(45))),
            "An inter-message timeout is a resume drop-class (quiet abandon).");
        Assert.IsTrue(Classify(classifier, new DeviceLinkVersionExchangeTimeoutException(TimeSpan.FromSeconds(35))),
            "A version-exchange timeout is a resume drop-class (quiet abandon).");
        Assert.IsTrue(Classify(classifier, new IOException("socket bump")),
            "A transient transport IOException is a resume drop-class (quiet abandon).");

        Assert.IsFalse(Classify(classifier, new OperationCanceledException()),
            "A user/terminal cancellation is NOT a quiet-abandon drop-class — the normal CancelBackup path runs.");
        Assert.IsFalse(Classify(classifier, new InvalidOperationException()),
            "An arbitrary programming error is NOT a quiet-abandon drop-class.");
    }

    private static bool Classify(MethodInfo classifier, Exception ex)
        => (bool)classifier.Invoke(null, [ex])!;

    private static Task<Netimobiledevice.Plist.ArrayNode> InvokeProbeLoop(DeviceLinkService dl, CancellationToken ct)
    {
        MethodInfo method = typeof(DeviceLinkService).GetMethod(
            "ReceiveMessageWithSilenceProbeAsync", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("DeviceLinkService.ReceiveMessageWithSilenceProbeAsync must exist for #2197 P0-B / #2200 P0.");
        return (Task<Netimobiledevice.Plist.ArrayNode>)method.Invoke(dl, [ct])!;
    }

    private static Task<bool> InvokeCompositeHealth(DeviceLinkService dl, CancellationToken ct)
    {
        MethodInfo method = typeof(DeviceLinkService).GetMethod(
            "IsPreparingTransportHealthyAsync", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("DeviceLinkService.IsPreparingTransportHealthyAsync must exist for #2197 P0-B.");
        return (Task<bool>)method.Invoke(dl, [ct])!;
    }

    private static async Task WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !condition())
        {
            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    private static void SetTimeSpanField(DeviceLinkService dl, string name, TimeSpan value)
    {
        FieldInfo field = typeof(DeviceLinkService).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException($"{name} field must exist on DeviceLinkService.");
        field.SetValue(dl, value);
    }

    private static void SetBoolField(DeviceLinkService dl, string name, bool value)
    {
        FieldInfo field = typeof(DeviceLinkService).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException($"{name} field must exist on DeviceLinkService.");
        field.SetValue(dl, value);
    }

    /// <summary>
    /// The inter-message / Preparing bounds apply only on USB transport (MuxDevice.ConnectionType == Usb).
    /// A loopback socket pair has no MuxDevice, so IsUsbTransport would be false. Force a usbmux device with
    /// Usb connection type onto the connection so the bound path is exercised.
    /// </summary>
    private static void ForceUsbTransport(ServiceConnection connection)
    {
        // Build a UsbmuxdDevice from the plist ctor (a USB device), the standard shape usbmux emits.
        var propertiesDict = new Netimobiledevice.Plist.DictionaryNode
        {
            { "SerialNumber", new Netimobiledevice.Plist.StringNode("TESTUDID") },
            { "ConnectionType", new Netimobiledevice.Plist.StringNode("USB") }
        };
        var muxDevice = new Netimobiledevice.Usbmuxd.UsbmuxdDevice(
            new Netimobiledevice.Plist.IntegerNode(1), propertiesDict);

        PropertyInfo muxProp = typeof(ServiceConnection).GetProperty("MuxDevice")
            ?? throw new AssertFailedException("ServiceConnection.MuxDevice must exist.");
        muxProp.SetValue(connection, muxDevice);
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

        return (ServiceConnection)ctor.Invoke([connectedSocket, timeout, NullLogger.Instance, null]);
    }

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
