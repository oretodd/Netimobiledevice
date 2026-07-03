using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Fork tests for #2197 (P0-C): <see cref="ServiceConnection.Close"/> / <see cref="ServiceConnection.Dispose"/>
/// must actually CLOSE THE SOCKET so the device gets a deterministic TCP FIN. Before the fix, Close only
/// disposed the active stream — with SSL up, disposing the SslStream (constructed leaveInnerStreamOpen:true)
/// never closed the socket-owning NetworkStream, leaving the connection abandoned half-open with no FIN.
/// </summary>
[TestClass]
public class ServiceConnectionSocketCloseTests
{
    [TestMethod]
    [Description("#2197 (P0-C): Close() disposes the socket-owning NetworkStream so the peer sees a real FIN " +
                 "(the accepted server-side read returns 0 bytes = EOF).")]
    public async Task Close_DisposesSocket_PeerSeesFin()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task<Socket> acceptTask = listener.AcceptSocketAsync();
        var clientSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);
        using Socket server = await acceptTask.ConfigureAwait(false);

        ServiceConnection connection = CreateServiceConnection(clientSocket, timeout: 5000);

        // No SSL established → the active Stream is the NetworkStream. Close() must tear the socket down.
        connection.Close();

        // The server end now reads EOF (0 bytes) — the deterministic FIN the device needs.
        var buffer = new byte[16];
        int read = await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
        Assert.AreEqual(0, read,
            "After ServiceConnection.Close() the peer must read 0 bytes (EOF) — a real TCP FIN was sent, not a half-open abandon.");
    }

    [TestMethod]
    [Description("#2197 (P0-C): Dispose() is idempotent-safe over Close() — disposing after (or instead of) " +
                 "Close must not throw, and the socket is torn down exactly once.")]
    public async Task Dispose_AfterClose_DoesNotThrow()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task<Socket> acceptTask = listener.AcceptSocketAsync();
        var clientSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);
        using Socket server = await acceptTask.ConfigureAwait(false);

        ServiceConnection connection = CreateServiceConnection(clientSocket, timeout: 5000);

        connection.Close();
        // A second teardown via Dispose must be safe (NetworkStream.Dispose is idempotent).
        connection.Dispose();

        var buffer = new byte[16];
        int read = await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
        Assert.AreEqual(0, read, "The peer still sees a clean EOF after Close()+Dispose().");
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
}
