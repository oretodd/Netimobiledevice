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
/// classification. These drive the private <c>ReceiveMessageWithPreparingProbeAsync</c> over a live
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
            "ReceiveMessageWithPreparingProbeAsync", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("DeviceLinkService.ReceiveMessageWithPreparingProbeAsync must exist for #2197 P0-B.");
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
