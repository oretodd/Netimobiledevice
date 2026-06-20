using Netimobiledevice.Lockdown;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Regression guard for #1999: the SSL trust handshake in
/// <see cref="ServiceConnection.StartSsl"/> / <see cref="ServiceConnection.StartSslAsync"/> must NOT
/// inherit the finite data-read timeout that the re-fork's <c>ServiceConnection</c> ctor stamps onto
/// the connection (default 10_000 ms). The device shows a trust/passcode dialog during
/// <c>AuthenticateAsClient</c> that legitimately takes longer than that budget; a finite stream
/// timeout makes the host abort the relay socket (SocketException 10053) and detection fails.
///
/// The fix runs the handshake with <see cref="Timeout.Infinite"/> and only restores the finite
/// <c>_timeout</c> afterwards (preserving the #1857 bulk-read protection, which is applied later via
/// <see cref="ServiceConnection.SetTimeout(int)"/>). These tests fail loudly if a future change (or
/// upstream merge) re-introduces a finite sub-passcode timeout on the handshake stream.
/// </summary>
[TestClass]
public class ServiceConnectionSslHandshakeTimeoutTests
{
    /// <summary>
    /// A deliberately short finite "data-read" timeout. The buggy behavior would abort the handshake
    /// at roughly this mark; the correct behavior blocks past it because the handshake runs Infinite.
    /// </summary>
    private const int FiniteTimeoutMs = 300;

    [TestMethod]
    [Description("StartSsl (synchronous) must run AuthenticateAsClient with an infinite stream timeout " +
                 "so a slow trust/passcode handshake cannot abort the socket at the finite data-read " +
                 "budget (#1999). The live failure was on this synchronous path — synchronous Stream.Read " +
                 "honors NetworkStream.ReadTimeout, so a finite timeout here aborts the handshake (10053).")]
    public async Task StartSsl_DoesNotAbortHandshakeAtFiniteTimeout()
    {
        // A loopback server that accepts the connection, reads the TLS ClientHello, then stalls —
        // never sending a ServerHello, so the client's synchronous handshake read blocks. If the
        // handshake stream carried the finite timeout, that read throws around FiniteTimeoutMs (the
        // #1999 regression); with the fix it blocks (Infinite) until we tear the connection down.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var serverGate = new ManualResetEventSlim(false);
        Task serverTask = Task.Run(async () =>
        {
            using Socket server = await listener.AcceptSocketAsync().ConfigureAwait(false);
            // Drain the ClientHello so the client believes the connection is live, then hold the
            // socket open (do nothing) until the test releases the gate.
            var buffer = new byte[4096];
            try
            {
                await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
            }
            catch
            {
                // The client may reset the socket when the test disposes the connection — ignore.
            }
            serverGate.Wait(TimeSpan.FromSeconds(10));
        });

        Socket clientSocket = new(SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);

        ServiceConnection connection = CreateServiceConnection(clientSocket, FiniteTimeoutMs);
        X509Certificate2 certificate = SelfSignedCertificate();

        // Drive the SYNCHRONOUS handshake on a background thread; it should NOT complete (return or
        // throw) within a window that is many multiples of the finite timeout. If it completes fast,
        // the finite timeout fired on the handshake stream — the regression we are guarding against.
        Task<bool> handshakeTask = Task.Run(() => connection.StartSsl(certificate));

        Task completed = await Task.WhenAny(handshakeTask, Task.Delay(FiniteTimeoutMs * 5)).ConfigureAwait(false);

        bool handshakeFinishedEarly = completed == handshakeTask;

        // Release the server and tear down so the (still-blocked) handshake unblocks and the test
        // exits cleanly regardless of outcome.
        serverGate.Set();
        connection.Dispose();
        try
        {
            await handshakeTask.ConfigureAwait(false);
        }
        catch
        {
            // Expected once the socket is torn down — we only care that it did not finish early.
        }
        certificate.Dispose();
        await serverTask.ConfigureAwait(false);

        Assert.IsFalse(handshakeFinishedEarly,
            $"StartSsl completed within {FiniteTimeoutMs * 5} ms while the server stalled the " +
            "handshake. That means the handshake stream carried the finite data-read timeout — the " +
            "#1999 regression (SocketException 10053). The handshake must run with Timeout.Infinite " +
            "(restoring the finite timeout only after AuthenticateAsClient).");
    }

    [TestMethod]
    [Description("After the handshake the finite data-read timeout must be restored onto the SSL " +
                 "stream so the #1857 bulk-read protection still applies (#1999).")]
    public void RestoreStreamTimeoutAfterHandshake_RestoresFiniteTimeoutOntoSslStream()
    {
        // Build a connection with the finite budget over its own loopback socket, install an
        // SslStream wrapping a second, independent loopback NetworkStream (one this connection does
        // NOT own, to avoid double-dispose), set it to the handshake-time Infinite state, then invoke
        // the private restore helper and assert it flips the stream back to the finite budget.
        using SocketPair connectionPair = SocketPair.CreateConnected();
        using SocketPair sslInnerPair = SocketPair.CreateConnected();

        ServiceConnection connection = CreateServiceConnection(connectionPair.Client, FiniteTimeoutMs);
        try
        {
            using var innerStream = new NetworkStream(sslInnerPair.Client, ownsSocket: false);
            using var sslStream = new System.Net.Security.SslStream(innerStream, leaveInnerStreamOpen: true)
            {
                // Simulate the handshake-time state the fix establishes before AuthenticateAsClient.
                ReadTimeout = Timeout.Infinite,
                WriteTimeout = Timeout.Infinite
            };

            FieldInfo? sslField = typeof(ServiceConnection).GetField("_sslStream",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(sslField, "_sslStream field must exist on ServiceConnection.");
            sslField!.SetValue(connection, sslStream);

            MethodInfo? restore = typeof(ServiceConnection).GetMethod(
                "RestoreStreamTimeoutAfterHandshake",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(restore,
                "ServiceConnection.RestoreStreamTimeoutAfterHandshake must exist — it restores the " +
                "finite data-read timeout after the handshake (#1999/#1857).");

            restore!.Invoke(connection, null);

            Assert.AreEqual(FiniteTimeoutMs, sslStream.ReadTimeout,
                "After the handshake the SSL stream ReadTimeout must be restored to the finite budget.");
            Assert.AreEqual(FiniteTimeoutMs, sslStream.WriteTimeout,
                "After the handshake the SSL stream WriteTimeout must be restored to the finite budget.");

            // Detach our SslStream before the connection disposes so its Dispose() does not also tear
            // down the stream we own here (avoids an ObjectDisposedException double-free).
            sslField.SetValue(connection, null);
        }
        finally
        {
            connection.Dispose();
        }
    }

    /// <summary>
    /// Construct a <see cref="ServiceConnection"/> over an already-connected socket with the given
    /// finite timeout, via the internal/private constructor (InternalsVisibleTo is set for this
    /// test assembly).
    /// </summary>
    private static ServiceConnection CreateServiceConnection(Socket connectedSocket, int timeout)
    {
        ConstructorInfo? ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(Netimobiledevice.Usbmuxd.UsbmuxdDevice)],
            modifiers: null);

        Assert.IsNotNull(ctor,
            "ServiceConnection(Socket, int, ILogger, UsbmuxdDevice?) constructor must exist for this test.");

        return (ServiceConnection)ctor!.Invoke(
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
    /// A connected loopback TCP socket pair (client + accepted server), disposed together.
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
            Client.Dispose();
            Server.Dispose();
        }
    }
}
