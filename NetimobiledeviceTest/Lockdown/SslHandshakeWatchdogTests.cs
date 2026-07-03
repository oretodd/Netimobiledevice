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
/// #2182: the SSL-handshake WATCHDOG. The handshake previously ran with <see cref="Timeout.Infinite"/>
/// (#1999) so a lost <c>close_notify</c> could hang forever; a policy-driven ~60s watchdog now bounds
/// ONLY the SSL wait and surfaces a bounded, classifiable <see cref="TimeoutException"/> that feeds
/// reconnect-and-resume. The bound comes from the <see cref="ServiceConnection.TimeoutPolicy"/> the
/// host assigns from <c>BackupConfiguration</c> (#2190 wiring), defaulting to
/// <see cref="TransportTimeoutPolicy.UsbTight"/>.
/// </summary>
[TestClass]
public class SslHandshakeWatchdogTests
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
}
