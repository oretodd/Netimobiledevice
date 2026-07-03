using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for the FIN empty-message spin fix (#2198, P1-2).
///
/// Background: on a peer FIN, <c>ReceiveAsync(4)</c> returns 0 bytes INSTANTLY, so
/// <c>ReceiveMessage</c> yields an empty message — and because every read RETURNS, no read CTS or
/// inter-message CTS can ever fire. DlLoop previously logged "no elements", slept 100 ms and looped
/// FOREVER. The fix counts consecutive empty messages: a second consecutive empty (or a single empty
/// with the socket probing dead/EOF) raises the SAME classifiable transport-drop signal as the
/// inter-message bound (<see cref="DeviceLinkInterMessageTimeoutException"/>), feeding
/// reconnect-and-resume. The counter resets on any non-empty message.
/// </summary>
[TestClass]
public class DeviceLinkEmptyMessageSpinTests
{
    [TestMethod]
    [Description("#2198 P1-2: a SINGLE empty message on a HEALTHY transport does NOT raise the drop signal (the historical benign shape is tolerated).")]
    public void SingleEmpty_HealthyTransport_DoesNotRaise()
    {
        Assert.IsFalse(DeviceLinkService.ShouldTreatEmptyMessagesAsTransportDrop(
            consecutiveEmptyMessages: 1, transportDead: false),
            "One empty message on a healthy socket must be tolerated — only deterministic FIN evidence raises the signal.");
    }

    [TestMethod]
    [Description("#2198 P1-2: a SECOND consecutive empty message raises the drop signal even when the socket poll still looks healthy.")]
    public void DoubleEmpty_Raises()
    {
        Assert.IsTrue(DeviceLinkService.ShouldTreatEmptyMessagesAsTransportDrop(
            consecutiveEmptyMessages: 2, transportDead: false),
            "A peer FIN makes every read return 0 bytes instantly, so a repeat empty is deterministic evidence — the spin must end in a classifiable drop, not delay-100ms-forever.");
    }

    [TestMethod]
    [Description("#2198 P1-2: a single empty message PLUS a dead socket poll (EOF/RST) raises immediately — no need to spin once more.")]
    public void SingleEmpty_DeadTransport_Raises()
    {
        Assert.IsTrue(DeviceLinkService.ShouldTreatEmptyMessagesAsTransportDrop(
            consecutiveEmptyMessages: 1, transportDead: true),
            "Empty + socket EOF is already transport evidence; the first occurrence must raise the drop signal.");
    }

    [TestMethod]
    [Description("#2198 P1-2: zero consecutive empties never raises (the reset-on-non-empty baseline).")]
    public void NoEmpties_DoesNotRaise()
    {
        Assert.IsFalse(DeviceLinkService.ShouldTreatEmptyMessagesAsTransportDrop(
            consecutiveEmptyMessages: 0, transportDead: false));
        Assert.IsFalse(DeviceLinkService.ShouldTreatEmptyMessagesAsTransportDrop(
            consecutiveEmptyMessages: 0, transportDead: true),
            "With no empty message observed there is nothing to classify — a dead poll alone is the keepalive/read path's job.");
    }

    [TestMethod]
    [Description("#2198 P1-2: the raised signal is the SAME type as the inter-message bound so it classifies identically everywhere (library quiet-abandon + host resume ladder).")]
    public void EmptyMessageDrop_UsesInterMessageSignalType()
    {
        DeviceLinkInterMessageTimeoutException ex = new(
            "Device link peer closed the connection (consecutive empty messages: 2, transportDead: False) — classifying as a transport drop",
            TimeSpan.FromSeconds(30));

        Assert.IsInstanceOfType<TimeoutException>(ex);
        Assert.AreEqual(TimeSpan.FromSeconds(30), ex.Bound);
        Assert.IsTrue(ex.Message.Contains("consecutive empty messages", StringComparison.Ordinal),
            "The custom-message overload names the FIN-spin shape for diagnostics while keeping the classifiable type.");
    }

    [TestMethod]
    [Timeout(15000)]
    [Description("#2198 P1-2 (failing-shape repro): a peer FIN mid-DlLoop ends the loop with the bounded transport-drop signal in ~ms — previously it spun log/delay-100ms FOREVER because every read returned.")]
    public async Task DlLoop_PeerFin_RaisesBoundedDropInsteadOfSpinningForever()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty,
            iosVersion: new Version(17, 0), logger: NullLogger.Instance);

        // The peer FINs the connection without ever sending a message — the exact Run-A shape.
        pair.Server.Shutdown(SocketShutdown.Send);

        Stopwatch sw = Stopwatch.StartNew();
        DeviceLinkInterMessageTimeoutException ex = await Assert.ThrowsExactlyAsync<DeviceLinkInterMessageTimeoutException>(
            () => dl.DlLoop(CancellationToken.None),
            "A peer FIN must surface the bounded, classifiable transport-drop signal — the empty-message spin (delay-100ms-forever) is the failure shape this fix removes.");
        sw.Stop();

        Assert.IsTrue(sw.Elapsed < TimeSpan.FromSeconds(10),
            $"The FIN must be classified promptly (elapsed {sw.ElapsedMilliseconds}ms), not after minutes of spinning.");
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
