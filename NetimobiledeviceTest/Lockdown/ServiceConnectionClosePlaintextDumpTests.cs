using Netimobiledevice.Lockdown;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// #2077: the in-library plaintext dump at the mb2 version-exchange FIN must distinguish a graceful
/// device close (TLS <c>close_notify</c> / clean FIN — Apple's mb2 logic deliberately refused
/// something) from a hard TCP <c>RST</c> (transport-level abort). That close_notify-vs-RST signal is
/// THE decisive USB-vs-WiFi discriminator. These tests drive
/// <see cref="ServiceConnection.ClassifyConnectionClose"/> over a real loopback socket pair so the
/// classifier is exercised against an actual graceful FIN and an actual RST
/// (<see cref="LingerOption"/> with a 0-second timeout forces a reset on close), plus cover the
/// pure hex-preview formatter and the version-exchange-window safety bound.
/// </summary>
[TestClass]
public class ServiceConnectionClosePlaintextDumpTests
{
    [TestMethod]
    [Description("A peer that shuts down and closes its socket cleanly produces a graceful close " +
                 "classification (close_notify / clean FIN), NOT an RST — #2077 AC3.")]
    public void ClassifyConnectionClose_GracefulFin_ReportsGraceful()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client);
        try
        {
            // Graceful close: half-close (send FIN) then close the server socket normally.
            pair.Server.Shutdown(SocketShutdown.Both);
            pair.Server.Close();

            // Give the FIN time to arrive at the client side.
            WaitForPeerClose(pair.Client);

            string result = InvokeClassifyConnectionClose(connection);

            StringAssert.StartsWith(result, "graceful",
                $"A clean FIN/close_notify must classify as graceful, got '{result}'.");
        }
        finally
        {
            connection.Dispose();
        }
    }

    [TestMethod]
    [Description("A peer that closes with a zero-linger socket sends a hard RST, which must classify " +
                 "as rst, NOT graceful — #2077 AC3 (the decisive transport-abort signal).")]
    public void ClassifyConnectionClose_HardReset_ReportsRst()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client);
        try
        {
            // LingerOption(enable: true, seconds: 0) forces the stack to send a RST on close instead
            // of the normal FIN handshake.
            pair.Server.LingerState = new LingerOption(true, 0);
            pair.Server.Close();

            WaitForPeerClose(pair.Client);

            string result = InvokeClassifyConnectionClose(connection);

            StringAssert.StartsWith(result, "rst",
                $"A zero-linger close sends a RST and must classify as rst, got '{result}'.");
        }
        finally
        {
            connection.Dispose();
        }
    }

    [TestMethod]
    [Description("FormatHexPreview renders a non-empty buffer as space-separated lowercase hex of the " +
                 "first <count> bytes — #2077 AC2 (decrypted partial bytes at the FIN).")]
    public void FormatHexPreview_RendersLowercaseSpacedHexOfFirstCountBytes()
    {
        byte[] buffer = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];

        string hex = ServiceConnection.FormatHexPreview(buffer, 4);

        Assert.AreEqual("de ad be ef", hex);
    }

    [TestMethod]
    [Description("FormatHexPreview returns <none> for a 0-byte read — the canonical 0/4 " +
                 "version-exchange FIN where no decrypted bytes were returned (#2077 AC2).")]
    public void FormatHexPreview_ZeroCount_ReturnsNone()
    {
        byte[] buffer = [0x01, 0x02];

        Assert.AreEqual("<none>", ServiceConnection.FormatHexPreview(buffer, 0));
        Assert.AreEqual("<none>", ServiceConnection.FormatHexPreview([], 0));
    }

    [TestMethod]
    [Description("FormatHexPreview caps the rendered bytes so a stray large read cannot balloon the " +
                 "log, appending a truncation marker with the omitted count.")]
    public void FormatHexPreview_CapsLargeBuffersWithTruncationMarker()
    {
        byte[] buffer = new byte[200];
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0xAB;
        }

        string hex = ServiceConnection.FormatHexPreview(buffer, buffer.Length);

        StringAssert.Contains(hex, "…", "A large buffer must be truncated with an ellipsis marker.");
        StringAssert.Contains(hex, "+136 more",
            "The truncation marker must report how many bytes were omitted (200 - 64 cap = 136).");
    }

    [TestMethod]
    [Description("HostBytesSent reflects the cumulative bytes the host wrote — the #2077 AC1 signal " +
                 "that proves whether the host sent a stray byte before the device-speaks-first read.")]
    public void HostBytesSent_TracksCumulativeHostWrites()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client);
        try
        {
            Assert.AreEqual(0L, connection.HostBytesSent,
                "A fresh connection must report zero host-sent bytes (device speaks first).");

            connection.Send([0x01, 0x02, 0x03]);

            Assert.AreEqual(3L, connection.HostBytesSent,
                "HostBytesSent must accumulate the bytes passed to Send.");
        }
        finally
        {
            connection.Dispose();
        }
    }

    [TestMethod]
    [Description("The version-exchange window is the safety bound: the plaintext dump only fires while " +
                 "the window is open. Begin/End must flip the gating flag so the transfer phase (user " +
                 "content) can never dump — #2077 load-bearing scope.")]
    public void VersionExchangeWindow_BeginAndEnd_FlipTheGatingFlag()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client);
        try
        {
            FieldInfo windowField = typeof(ServiceConnection).GetField("_versionExchangeWindow",
                BindingFlags.NonPublic | BindingFlags.Instance)
                ?? throw new AssertFailedException("_versionExchangeWindow field must exist.");

            Assert.IsFalse((bool)windowField.GetValue(connection)!,
                "The dump window must default closed — nothing dumps unless a version exchange arms it.");

            connection.BeginVersionExchangeWindow();
            Assert.IsTrue((bool)windowField.GetValue(connection)!,
                "BeginVersionExchangeWindow must open the dump window.");

            connection.EndVersionExchangeWindow();
            Assert.IsFalse((bool)windowField.GetValue(connection)!,
                "EndVersionExchangeWindow must close the window before the transfer phase.");
        }
        finally
        {
            connection.Dispose();
        }
    }

    private static string InvokeClassifyConnectionClose(ServiceConnection connection)
    {
        MethodInfo method = typeof(ServiceConnection).GetMethod("ClassifyConnectionClose",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("ServiceConnection.ClassifyConnectionClose must exist.");
        return (string)method.Invoke(connection, null)!;
    }

    /// <summary>
    /// Poll the local socket until the peer's FIN/RST is observable (readable with 0 available, or
    /// error condition), bounded so a misbehaving test cannot hang.
    /// </summary>
    private static void WaitForPeerClose(Socket socket)
    {
        for (int i = 0; i < 50; i++)
        {
            if (socket.Poll(0, SelectMode.SelectError) ||
                (socket.Poll(0, SelectMode.SelectRead) && SafeAvailable(socket) == 0))
            {
                return;
            }
            Thread.Sleep(20);
        }
    }

    private static int SafeAvailable(Socket socket)
    {
        try
        {
            return socket.Available;
        }
        catch (SocketException)
        {
            // A pending RST can make Available throw — treat as "peer closed".
            return 0;
        }
    }

    /// <summary>
    /// Construct a <see cref="ServiceConnection"/> over an already-connected socket via the
    /// internal/private constructor (InternalsVisibleTo is set for this test assembly).
    /// </summary>
    private static ServiceConnection CreateServiceConnection(Socket connectedSocket)
    {
        ConstructorInfo ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(Netimobiledevice.Usbmuxd.UsbmuxdDevice)],
            modifiers: null)
            ?? throw new AssertFailedException(
                "ServiceConnection(Socket, int, ILogger, UsbmuxdDevice?) constructor must exist for this test.");

        return (ServiceConnection)ctor.Invoke(
            [connectedSocket, Timeout.Infinite, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, null]);
    }

    /// <summary>
    /// A connected loopback TCP socket pair (client + accepted server), disposed together.
    /// Mirrors the helper in <c>ServiceConnectionSslHandshakeTimeoutTests</c>.
    /// </summary>
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
