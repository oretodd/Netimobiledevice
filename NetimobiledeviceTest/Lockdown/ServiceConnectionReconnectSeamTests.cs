using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;
using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// #2182: the SSL-handshake WATCHDOG and the SESSION-PRESERVING RECONNECT SEAM.
///
/// The handshake previously ran with <see cref="Timeout.Infinite"/> (#1999) so a lost
/// <c>close_notify</c> could hang forever; a policy-driven ~60s watchdog now bounds ONLY the SSL wait
/// and surfaces a bounded, classifiable <see cref="TimeoutException"/> that feeds reconnect-and-resume.
///
/// The reconnect seam (<see cref="ServiceConnection.AdoptTransportFrom"/>) swaps the underlying socket
/// beneath the SAME <see cref="ServiceConnection"/> instance so the mb2 session (and its once-per-
/// session passcode grant) is NOT recreated. These tests drive both over real loopback sockets.
/// </summary>
[TestClass]
public class ServiceConnectionReconnectSeamTests
{
    /// <summary>A short handshake watchdog so the stalled-handshake test trips quickly.</summary>
    private const int WatchdogSec = 1;

    [TestMethod]
    [Description("#2182: a stalled handshake (server accepts, reads ClientHello, then never replies — " +
                 "the lost-close_notify signature) must TRIP the SSL-handshake watchdog with a bounded " +
                 "TimeoutException instead of hanging at Timeout.Infinite. Sync StartSsl path.")]
    public async Task StartSsl_StalledHandshake_TripsWatchdog_InsteadOfHanging()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var serverGate = new ManualResetEventSlim(false);
        Task serverTask = Task.Run(async () =>
        {
            using Socket server = await listener.AcceptSocketAsync().ConfigureAwait(false);
            var buffer = new byte[4096];
            try
            {
                await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
            }
            catch
            {
                // Client may reset on teardown — ignore.
            }
            serverGate.Wait(TimeSpan.FromSeconds(10));
        });

        Socket clientSocket = new(SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);

        ServiceConnection connection = CreateServiceConnection(clientSocket, Timeout.Infinite);
        connection.TimeoutPolicy = ShortWatchdogPolicy();
        X509Certificate2 certificate = SelfSignedCertificate();

        // Drive the synchronous handshake on a worker; it must throw the bounded TimeoutException
        // well within a window that is many multiples of the watchdog bound. If it never returns, the
        // watchdog did not bound the handshake — the #2182 regression.
        Task<bool> handshakeTask = Task.Run(() => connection.StartSsl(certificate));
        Task completed = await Task.WhenAny(
            handshakeTask,
            Task.Delay(TimeSpan.FromSeconds(WatchdogSec * 8))).ConfigureAwait(false);

        Assert.AreSame(handshakeTask, completed,
            $"StartSsl did not return within {WatchdogSec * 8}s while the server stalled the handshake — " +
            "the SSL-handshake watchdog (#2182) failed to bound the handshake and it hung.");

        await Assert.ThrowsExactlyAsync<TimeoutException>(async () => await handshakeTask.ConfigureAwait(false),
            "A stalled handshake must surface a bounded TimeoutException (the classifiable transport-drop signal).");

        serverGate.Set();
        connection.Dispose();
        certificate.Dispose();
        await serverTask.ConfigureAwait(false);
    }

    [TestMethod]
    [Description("#2182: the async StartSslAsync path also trips the watchdog on a stalled handshake, " +
                 "surfacing the bounded TimeoutException rather than hanging at Timeout.Infinite.")]
    public async Task StartSslAsync_StalledHandshake_TripsWatchdog()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var serverGate = new ManualResetEventSlim(false);
        Task serverTask = Task.Run(async () =>
        {
            using Socket server = await listener.AcceptSocketAsync().ConfigureAwait(false);
            var buffer = new byte[4096];
            try
            {
                await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
            }
            catch
            {
                // Ignore teardown resets.
            }
            serverGate.Wait(TimeSpan.FromSeconds(10));
        });

        Socket clientSocket = new(SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);

        ServiceConnection connection = CreateServiceConnection(clientSocket, Timeout.Infinite);
        connection.TimeoutPolicy = ShortWatchdogPolicy();
        X509Certificate2 certificate = SelfSignedCertificate();

        Task<bool> handshakeTask = connection.StartSslAsync(certificate);
        Task completed = await Task.WhenAny(
            handshakeTask,
            Task.Delay(TimeSpan.FromSeconds(WatchdogSec * 8))).ConfigureAwait(false);

        Assert.AreSame(handshakeTask, completed,
            $"StartSslAsync did not complete within {WatchdogSec * 8}s while the server stalled — the " +
            "async watchdog (#2182) failed to bound the handshake.");

        await Assert.ThrowsExactlyAsync<TimeoutException>(async () => await handshakeTask.ConfigureAwait(false),
            "The async watchdog must surface a bounded TimeoutException on a stalled handshake.");

        serverGate.Set();
        connection.Dispose();
        certificate.Dispose();
        await serverTask.ConfigureAwait(false);
    }

    [TestMethod]
    [Description("#2182 reconnect seam: AdoptTransportFrom swaps the underlying socket beneath the " +
                 "SAME ServiceConnection instance (no session recreation). After the swap, the SAME " +
                 "instance is live on the fresh transport and the old socket is torn down.")]
    public void AdoptTransportFrom_SwapsSocket_RetainsSameInstance()
    {
        using SocketPair oldPair = SocketPair.CreateConnected();
        using SocketPair freshPair = SocketPair.CreateConnected();

        ServiceConnection preserved = CreateServiceConnection(oldPair.Client, 5000);
        ServiceConnection fresh = CreateServiceConnection(freshPair.Client, Timeout.Infinite);

        // Capture identity + the old underlying socket before the swap.
        Socket oldSocket = UnderlyingSocket(preserved);
        Socket freshSocket = UnderlyingSocket(fresh);
        Assert.AreNotSame(oldSocket, freshSocket, "Precondition: the two connections use different sockets.");

        preserved.AdoptTransportFrom(fresh);

        // The SAME ServiceConnection instance now rides the fresh socket — this is what preserves the
        // mb2 session (the owner keeps its reference; only the transport underneath changed).
        Assert.AreSame(freshSocket, UnderlyingSocket(preserved),
            "After AdoptTransportFrom the preserved instance must ride the fresh transport's socket.");

        // The preserved instance's configured read timeout must carry across the swap (#1857 budget).
        Assert.AreEqual(5000, preserved.Stream.ReadTimeout,
            "The preserved connection's configured data-read timeout must be re-applied to the adopted stream.");

        // The old socket must be torn down (the swap owns old-transport teardown).
        Assert.IsFalse(SocketIsUsable(oldSocket),
            "The old socket must be disposed/closed by the swap — it owns old-transport teardown.");

        // The neutralized fresh wrapper must be a safe-to-discard shell: disposing it is a no-op and
        // must NOT close the transplanted socket the preserved instance now owns.
        fresh.Dispose();
        Assert.IsTrue(preserved.IsConnected,
            "Disposing the neutralized fresh wrapper must not close the transplanted transport.");

        preserved.Dispose();
    }

    [TestMethod]
    [Description("#2182 reconnect seam: after a swap, the preserved connection can send/receive over " +
                 "the fresh transport — proving the transplant produced a live, usable connection.")]
    public void AdoptTransportFrom_ProducesLiveConnection()
    {
        using SocketPair oldPair = SocketPair.CreateConnected();
        using SocketPair freshPair = SocketPair.CreateConnected();

        ServiceConnection preserved = CreateServiceConnection(oldPair.Client, 5000);
        ServiceConnection fresh = CreateServiceConnection(freshPair.Client, Timeout.Infinite);
        try
        {
            preserved.AdoptTransportFrom(fresh);

            // Server side of the FRESH pair sends 4 bytes; the preserved connection must read them
            // over the adopted transport.
            byte[] payload = [0x01, 0x02, 0x03, 0x04];
            freshPair.Server.Send(payload);

            byte[] received = preserved.Receive(4);

            CollectionAssert.AreEqual(payload, received,
                "The preserved connection must read bytes sent over the adopted (fresh) transport.");
        }
        finally
        {
            preserved.Dispose();
        }
    }

    [TestMethod]
    [Description("#2182: AdoptTransportFrom rejects adopting a connection's own transport (a no-op " +
                 "swap that would leave the instance in an invalid state).")]
    public void AdoptTransportFrom_SelfAdopt_Throws()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, 5000);
        try
        {
            Assert.ThrowsExactly<InvalidOperationException>(() => connection.AdoptTransportFrom(connection));
        }
        finally
        {
            connection.Dispose();
        }
    }

    private static TransportTimeoutPolicy ShortWatchdogPolicy()
    {
        // A policy identical to USB-tight but with a short watchdog so the stalled-handshake tests
        // trip quickly. All other bounds keep valid (positive) values.
        return new TransportTimeoutPolicy(
            readTimeoutMs: Timeout.Infinite,
            keepAliveTimeSec: 120,
            keepAliveIntervalSec: 30,
            keepAliveRetryCount: 10,
            sslHandshakeWatchdogSec: WatchdogSec,
            interMessageSilenceBoundSec: 45);
    }

    private static Socket UnderlyingSocket(ServiceConnection connection)
    {
        FieldInfo field = typeof(ServiceConnection).GetField("_networkStream",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("_networkStream field must exist on ServiceConnection.");
        NetworkStream stream = (NetworkStream)field.GetValue(connection)!;
        return stream.Socket;
    }

    private static bool SocketIsUsable(Socket socket)
    {
        try
        {
            // A disposed socket throws ObjectDisposedException on Connected; a live socket returns.
            _ = socket.Connected;
            _ = socket.Available;
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
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
            [connectedSocket, timeout, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, null]);
    }

    private static X509Certificate2 SelfSignedCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new CertificateRequest("CN=ScribeHoldTest", rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    /// <summary>
    /// A connected loopback TCP socket pair (client + accepted server), disposed together. Mirrors
    /// the helper in the sibling ServiceConnection tests.
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
