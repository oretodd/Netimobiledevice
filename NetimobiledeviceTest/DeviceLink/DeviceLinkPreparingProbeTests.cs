using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for #2197 (P0-B): "probe, don't tear down, on a Preparing-bound trip". When the generous
/// Preparing silence bound trips during the pre-first-file window, the DlLoop runs a passive transport
/// health check; if the transport is HEALTHY (device still building its on-device manifest diff) it keeps
/// waiting under a total-continuous hard cap. It tears down (surfaces the bounded transport-drop signal)
/// ONLY on transport evidence (probe says dead) or hard-cap exhaustion.
///
/// These pin the pure decision (<see cref="DeviceLinkService.ShouldContinuePreparingWait"/>) and the
/// passive socket probe (<see cref="ServiceConnection.IsTransportHealthy"/>) with a live loopback socket
/// pair — the decisive pieces — without needing a full mb2 device.
/// </summary>
[TestClass]
public class DeviceLinkPreparingProbeTests
{
    // ── The pure keep-waiting decision ──────────────────────────────────────────────────────────────

    [TestMethod]
    [Description("#2197 (P0-B): keep waiting ONLY when the transport is healthy AND total continuous " +
                 "Preparing silence is still within the hard cap.")]
    public void ShouldContinuePreparingWait_HealthyAndWithinCap_KeepsWaiting()
    {
        Assert.IsTrue(DeviceLinkService.ShouldContinuePreparingWait(
            transportHealthy: true, totalPreparingSilence: TimeSpan.FromMinutes(3), hardCap: TimeSpan.FromMinutes(20)),
            "A healthy transport still within the hard cap means the device is still diffing — keep waiting.");
    }

    [TestMethod]
    [Description("#2197 (P0-B): a DEAD transport stops the wait immediately (tear down on transport evidence), " +
                 "even well within the hard cap.")]
    public void ShouldContinuePreparingWait_DeadTransport_StopsWaiting()
    {
        Assert.IsFalse(DeviceLinkService.ShouldContinuePreparingWait(
            transportHealthy: false, totalPreparingSilence: TimeSpan.FromSeconds(1), hardCap: TimeSpan.FromMinutes(20)),
            "A dead-peer probe verdict must tear down immediately, regardless of the hard cap.");
    }

    [TestMethod]
    [Description("#2197 (P0-B): an exhausted hard cap stops the wait even when the transport still probes " +
                 "healthy — a genuinely wedged Preparing window can never hang forever.")]
    public void ShouldContinuePreparingWait_HardCapExhausted_StopsWaiting()
    {
        Assert.IsFalse(DeviceLinkService.ShouldContinuePreparingWait(
            transportHealthy: true, totalPreparingSilence: TimeSpan.FromMinutes(20), hardCap: TimeSpan.FromMinutes(20)),
            "At the hard cap the wait must stop even if the transport still probes healthy (>= is exhausted).");
        Assert.IsFalse(DeviceLinkService.ShouldContinuePreparingWait(
            transportHealthy: true, totalPreparingSilence: TimeSpan.FromMinutes(21), hardCap: TimeSpan.FromMinutes(20)),
            "Beyond the hard cap the wait must stop.");
    }

    // ── The passive socket probe ────────────────────────────────────────────────────────────────────

    [TestMethod]
    [Description("#2197 (P0-B): a live, connected, quiet socket (peer present but not sending — the device " +
                 "diffing) probes HEALTHY, so the DlLoop keeps waiting.")]
    public void IsTransportHealthy_LiveQuietSocket_ReportsHealthy()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        try
        {
            Assert.IsTrue(connection.IsTransportHealthy(),
                "A connected socket with no pending data is the device-still-diffing signature — must probe healthy.");
        }
        finally
        {
            // Detach: the server end is disposed by the pair; avoid double-tearing via the connection.
            pair.Server.Dispose();
        }
    }

    [TestMethod]
    [Description("#2197 (P0-B): after the peer closes its end (FIN), the socket probes DEAD, so the DlLoop " +
                 "tears down and surfaces the bounded transport-drop signal.")]
    public void IsTransportHealthy_PeerClosed_ReportsDead()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);

        // The peer (server) closes its end — the client now sees a readable socket with 0 bytes available
        // (a received FIN), the dead-peer signature.
        pair.Server.Shutdown(SocketShutdown.Both);
        pair.Server.Close();

        // Give the FIN a moment to land on the client side.
        SpinWaitUntil(() => pair.Client.Poll(0, SelectMode.SelectRead), TimeSpan.FromSeconds(2));

        Assert.IsFalse(connection.IsTransportHealthy(),
            "A peer FIN (readable socket, 0 bytes available) must probe DEAD so the loop tears down on transport evidence.");
    }

    // ── The presence-probe hook (optional, default-null) ────────────────────────────────────────────

    [TestMethod]
    [Description("#2197 (P0-B): the DevicePresenceProbe hook is optional and default-null on a fresh " +
                 "DeviceLinkService, so a standalone consumer uses the socket probe alone.")]
    public void PresenceProbe_DefaultsToNull()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        Assert.IsNull(dl.PresenceProbe, "The presence-probe hook must default to null (socket-only) until the host wires it.");
    }

    [TestMethod]
    [Description("#2197 (P0-B): the ctor seeds the version-exchange bound and the Preparing hard cap from the " +
                 "connection's TransportTimeoutPolicy so the host config values take effect.")]
    public void Ctor_SeedsVersionExchangeAndHardCapFromConnectionPolicy()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, timeout: 5000);
        connection.TimeoutPolicy = TransportTimeoutPolicy.ForUsb(
            sslHandshakeWatchdogSec: 60, interMessageSilenceBoundSec: 30, preparingSilenceBoundSec: 240,
            versionExchangeBoundSec: 42, preparingHardCapSec: 1000);

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        Assert.AreEqual(TimeSpan.FromSeconds(42), ReadField(dl, "_usbVersionExchangeBound"),
            "The version-exchange bound must be seeded from the connection's policy.");
        Assert.AreEqual(TimeSpan.FromSeconds(1000), ReadField(dl, "_usbPreparingHardCap"),
            "The Preparing hard cap must be seeded from the connection's policy.");
    }

    // ── #2197 (P0-E): the per-exchange status extractor ─────────────────────────────────────────────

    [TestMethod]
    [Description("#2197 (P0-E): ExtractStatusCode returns the ErrorCode carried by a DLMessageProcessMessage " +
                 "and a sentinel for messages that have no status field — the diagnostic trace must never throw.")]
    public void ExtractStatusCode_ProcessMessageVsOthers()
    {
        ArrayNode processMessage = [
            new StringNode("DLMessageProcessMessage"),
            new DictionaryNode { { "ErrorCode", new IntegerNode(0) } }
        ];
        Assert.AreEqual(0L, DeviceLinkService.ExtractStatusCode("DLMessageProcessMessage", processMessage),
            "A DLMessageProcessMessage carries the ErrorCode as its status.");

        ArrayNode nonError = [
            new StringNode("DLMessageProcessMessage"),
            new DictionaryNode { { "ErrorCode", new IntegerNode(7) } }
        ];
        Assert.AreEqual(7L, DeviceLinkService.ExtractStatusCode("DLMessageProcessMessage", nonError));

        ArrayNode downloadFiles = [new StringNode("DLMessageDownloadFiles"), new ArrayNode()];
        Assert.AreEqual(long.MinValue, DeviceLinkService.ExtractStatusCode("DLMessageDownloadFiles", downloadFiles),
            "A message with no status field must return the sentinel, not throw.");

        // A malformed ProcessMessage body must not throw — sentinel is returned.
        ArrayNode malformed = [new StringNode("DLMessageProcessMessage")];
        Assert.AreEqual(long.MinValue, DeviceLinkService.ExtractStatusCode("DLMessageProcessMessage", malformed),
            "A malformed ProcessMessage (no body) must degrade to the sentinel, never throw into the trace.");
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    private static TimeSpan ReadField(DeviceLinkService dl, string name)
    {
        FieldInfo field = typeof(DeviceLinkService).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException($"{name} field must exist on DeviceLinkService.");
        return (TimeSpan)field.GetValue(dl)!;
    }

    private static void SpinWaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !condition())
        {
            Thread.Sleep(10);
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

        return (ServiceConnection)ctor.Invoke([connectedSocket, timeout, NullLogger.Instance, null]);
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
