using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Fork tests for the bounded async send (#2198, P1-1).
///
/// Background: <c>ServiceConnection.SendAsync</c> was a bare <c>Stream.WriteAsync</c> with no time
/// bound — <c>Stream.WriteTimeout</c> is sync-only in .NET — so a stalled backupd could park a
/// mid-payload write forever (the best-evidence mechanism of the original 51-minute wedge; TCP
/// keepalive cannot trip because the TCP peer is the local usbmuxd). The fix bounds EVERY async write
/// PER ~64KB CHUNK with a fresh CTS per chunk (the ReceiveAsync per-op pattern), gated by the
/// transport policy: USB gets a tight <see cref="TransportTimeoutPolicy.WriteBoundSec"/>; WiFi
/// disables the bound (0) so its write behavior is untouched.
/// </summary>
[TestClass]
public class ServiceConnectionSendTimeoutTests
{
    [TestMethod]
    [Timeout(20000)]
    [Description("#2198 P1-1: a blocked write (peer not draining, send buffers full) trips the policy write bound as a classifiable send-timeout — provably NOT parked forever.")]
    public async Task BlockedWrite_TripsWriteBound_AsClassifiableSendTimeout()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        // Shrink both sides' buffers so a large write cannot be absorbed by the kernel: the client's
        // WriteAsync then genuinely blocks on the peer draining — which it never does (the stalled-
        // backupd model).
        pair.Client.SendBufferSize = 8 * 1024;
        pair.Server.ReceiveBufferSize = 8 * 1024;

        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 60_000);
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: 1);

        byte[] payload = new byte[4 * 1024 * 1024];
        Stopwatch sw = Stopwatch.StartNew();

        ServiceConnectionSendTimeoutException ex = await Assert.ThrowsExactlyAsync<ServiceConnectionSendTimeoutException>(
            () => connection.SendAsync(payload, CancellationToken.None),
            "A write the peer never drains must trip the per-chunk write bound, not park forever.");
        sw.Stop();

        Assert.AreEqual(TimeSpan.FromSeconds(1), ex.Bound, "The signal carries the bound that tripped.");
        Assert.IsTrue(sw.Elapsed < TimeSpan.FromSeconds(15),
            $"The bound must trip near the configured 1s (elapsed {sw.ElapsedMilliseconds}ms), far below an unbounded/10-minute wait.");
    }

    [TestMethod]
    [Description("#2198 P1-1: the send timeout derives from TimeoutException (rides the host's existing transient TimeoutException ladder) with the classifiable 'Timeout sending to service' message.")]
    public void SendTimeout_IsClassifiableTimeoutSignal()
    {
        ServiceConnectionSendTimeoutException ex = new(TimeSpan.FromSeconds(60));

        Assert.IsInstanceOfType<TimeoutException>(ex,
            "The send timeout must derive from TimeoutException so the host's existing catch (TimeoutException) transient arm routes it into reconnect-and-resume.");
        Assert.IsTrue(ex.Message.StartsWith("Timeout sending to service", StringComparison.Ordinal),
            "The message names the send direction so a live wedge self-explains (the receive twin says 'Timeout waiting for message from service').");
        Assert.AreEqual(TimeSpan.FromSeconds(60), ex.Bound);
    }

    [TestMethod]
    [Description("#2198 P1-1: the WiFi-loose policy DISABLES the write bound (WriteBoundSec == 0) — WiFi async write behavior is untouched.")]
    public void WiFiLoosePolicy_DisablesWriteBound()
    {
        Assert.AreEqual(0, TransportTimeoutPolicy.WiFiLoose.WriteBoundSec,
            "WiFi must keep unbounded writes — the fork adds no WiFi change; the bound is USB-gated via the policy object.");

        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        connection.TimeoutPolicy = TransportTimeoutPolicy.WiFiLoose;

        Assert.AreEqual(Timeout.Infinite, connection.ResolveWriteBoundMs(),
            "A disabled (0) policy bound must resolve to Infinite — the bare-WriteAsync legacy path.");
    }

    [TestMethod]
    [Description("#2198 P1-1: the USB-tight policy enables a 60s default write bound, and ForUsb plumbs a host-configured value.")]
    public void UsbPolicy_CarriesWriteBound()
    {
        Assert.AreEqual(TransportTimeoutPolicy.DefaultWriteBoundSec, TransportTimeoutPolicy.UsbTight.WriteBoundSec,
            "USB must default to the tight library write bound.");
        Assert.AreEqual(60, TransportTimeoutPolicy.UsbTight.WriteBoundSec,
            "The USB write bound is the ~60s design value from #2198 P1-1.");

        TransportTimeoutPolicy hostPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: 42);
        Assert.AreEqual(42, hostPolicy.WriteBoundSec, "ForUsb must plumb the host-configured write bound.");
    }

    [TestMethod]
    [Description("#2198 P1-1: bound resolution — the policy bound applies unless the caller set a strictly TIGHTER Stream.WriteTimeout (the ReceiveAsync per-op mirror); the stream's loose 10-minute bulk timeout never loosens the policy.")]
    public void ResolveWriteBound_PolicyGatesAndTighterStreamTimeoutWins()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        // ServiceConnection ctor applies `timeout` as the stream Read/WriteTimeout.
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 600_000);
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: 60);

        Assert.AreEqual(60_000, connection.ResolveWriteBoundMs(),
            "With the stream at the loose 10-minute bulk timeout, the tight policy bound (60s) must govern.");

        connection.SetTimeout(5_000);
        Assert.AreEqual(5_000, connection.ResolveWriteBoundMs(),
            "A caller-set Stream.WriteTimeout tighter than the policy must be honored (per-op CTS mirror of ReceiveAsync).");
    }

    [TestMethod]
    [Description("#2198 P1-1: a negative WriteBoundSec is rejected; 0 (disabled) is accepted.")]
    public void WriteBound_Validation()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new TransportTimeoutPolicy(
            readTimeoutMs: 1000, keepAliveTimeSec: 120, keepAliveIntervalSec: 30, keepAliveRetryCount: 10,
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: -1));

        TransportTimeoutPolicy disabled = new TransportTimeoutPolicy(
            readTimeoutMs: 1000, keepAliveTimeSec: 120, keepAliveIntervalSec: 30, keepAliveRetryCount: 10,
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: 0);
        Assert.AreEqual(0, disabled.WriteBoundSec);
        Assert.AreEqual(TimeSpan.Zero, disabled.WriteBound);
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2198 P1-1: a healthy (drained) large send completes normally under the bound — the per-chunk granularity never clips a slow-but-moving transfer.")]
    public async Task DrainedLargeSend_CompletesUnderPerChunkBound()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 60_000);
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, writeBoundSec: 2);

        byte[] payload = new byte[2 * 1024 * 1024];
        new Random(42).NextBytes(payload);

        // A draining peer: read everything the client sends.
        byte[] received = new byte[payload.Length];
        Task drain = Task.Run(async () => {
            int total = 0;
            while (total < received.Length) {
                int n = await pair.Server.ReceiveAsync(received.AsMemory(total), SocketFlags.None);
                if (n == 0) { break; }
                total += n;
            }
        });

        await connection.SendAsync(payload, CancellationToken.None);
        await drain;

        CollectionAssert.AreEqual(payload, received,
            "Chunked bounded sends must deliver the exact same byte stream as the prior single WriteAsync.");
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
