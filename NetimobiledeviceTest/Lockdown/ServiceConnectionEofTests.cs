using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Netimobiledevice.Backup;
using Netimobiledevice.Lockdown;
using Netimobiledevice.NotificationProxy;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.Lockdown;

[TestClass]
public class ServiceConnectionEofTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [Timeout(15000)]
    [DataRow(5000)]
    [DataRow(Timeout.Infinite)]
    public async Task ReceiveAsync_PeerClosesMidRead_ThrowsEndOfStream(int timeout)
    {
        using SocketPair pair = SocketPair.CreateConnected();
        await using ServiceConnection connection = CreateServiceConnection(pair.Client, timeout);

        pair.Server.Send([0x01, 0x02]);
        pair.Server.Shutdown(SocketShutdown.Send);

        await Assert.ThrowsExactlyAsync<EndOfStreamException>(
            async () => await connection.ReceiveAsync(4, TestContext.CancellationToken));
    }

    [TestMethod]
    [Timeout(15000)]
    public void Receive_PeerClosesMidRead_ThrowsEndOfStream()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using ServiceConnection connection = CreateServiceConnection(pair.Client, 5000);

        pair.Server.Send([0x01]);
        pair.Server.Shutdown(SocketShutdown.Send);

        Assert.ThrowsExactly<EndOfStreamException>(() => connection.Receive(4));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task DeviceLinkReadInt32_ShortHeader_IsResumableIoDrop()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, 5000);
        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty,
            iosVersion: new Version(17, 0), logger: NullLogger.Instance);

        pair.Server.Send([0x00, 0x00]);
        pair.Server.Shutdown(SocketShutdown.Send);

        MethodInfo readInt32 = typeof(DeviceLinkService).GetMethod("ReadInt32", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new AssertFailedException("DeviceLinkService.ReadInt32 must exist for this test.");

        Exception ex = await Assert.ThrowsAsync<IOException>(
            () => (Task<int>)readInt32.Invoke(dl, [TestContext.CancellationToken])!);
        Assert.IsInstanceOfType<EndOfStreamException>(ex);
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task DeviceLinkReceiveMessage_PeerFin_ReturnsEmptyMessage()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, 5000);
        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty,
            iosVersion: new Version(17, 0), logger: NullLogger.Instance);

        pair.Server.Shutdown(SocketShutdown.Send);

        ArrayNode message = await dl.ReceiveMessage(TestContext.CancellationToken);

        Assert.IsEmpty(message);
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task NotificationProxyReceive_PeerFin_EndsWithExceptionInsteadOfYieldingForever()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        ServiceConnection connection = CreateServiceConnection(pair.Client, 5000);

        var lockdown = new Mock<LockdownServiceProvider>();
        lockdown.SetupGet(x => x.Logger).Returns(NullLogger.Instance);
        lockdown.SetupGet(x => x.OsVersion).Returns(new Version(17, 0));
        lockdown
            .Setup(x => x.StartLockdownServiceAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(connection);

        await using var proxy = new NotificationProxyService(lockdown.Object);
        await proxy.ConnectAsync(TestContext.CancellationToken);

        pair.Server.Shutdown(SocketShutdown.Send);

        int yielded = 0;
        await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
        {
            await foreach (DictionaryNode _ in proxy.ReceiveNotificationAsync(TestContext.CancellationToken))
            {
                yielded++;
            }
        });
        Assert.AreEqual(0, yielded);
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
