using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for #2197 (P0-C): the DeviceLinkService teardown paths.
/// <list type="bullet">
/// <item><see cref="DeviceLinkService.Dispose"/> sends DLMessageDisconnect (the normal/terminal path) then
/// closes the socket, and does so unreachable-proof (a throwing Disconnect still closes the socket).</item>
/// <item><see cref="DeviceLinkService.DisposeQuietly"/> is the quiet-abandon path — it does NOT send
/// DLMessageDisconnect (which would tell a busy device to tear down the session we intend to resume), but
/// still closes the socket for a deterministic FIN.</item>
/// </list>
/// </summary>
[TestClass]
public class DeviceLinkServiceDisposeTests
{
    [TestMethod]
    [Description("#2197 (P0-C): DisposeQuietly does NOT write a DLMessageDisconnect to the peer (quiet abandon) " +
                 "but still closes the socket (peer reads EOF).")]
    public async Task DisposeQuietly_SkipsDisconnect_ButClosesSocket()
    {
        (ServiceConnection connection, Socket server, Socket _) = CreatePair();

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        dl.DisposeQuietly();

        // The ONLY bytes the peer should ever see are the FIN (0-byte read). If a DLMessageDisconnect had
        // been written, the first read would return >0 bytes (the length-prefixed plist).
        var buffer = new byte[256];
        int read = await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
        Assert.AreEqual(0, read,
            "DisposeQuietly must NOT send DLMessageDisconnect — the peer should read only EOF (0 bytes). " +
            "Any payload here means the quiet-abandon path leaked a Disconnect that would cancel the resume target.");

        server.Dispose();
    }

    [TestMethod]
    [Description("#2197 (P0-C): Dispose (the normal path) DOES write a DLMessageDisconnect to the peer, then " +
                 "closes the socket.")]
    public async Task Dispose_SendsDisconnect_ThenClosesSocket()
    {
        (ServiceConnection connection, Socket server, Socket _) = CreatePair();

        using var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        dl.Dispose();

        // The peer first receives the DLMessageDisconnect payload (>0 bytes), then EOF.
        var buffer = new byte[512];
        int firstRead = await server.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
        Assert.IsTrue(firstRead > 0,
            "Dispose (the normal/terminal path) must send DLMessageDisconnect — the peer should read the payload first.");

        server.Dispose();
    }

    [TestMethod]
    [Description("#2197 (P0-C): Dispose is unreachable-proof — even if the socket is already gone so the " +
                 "DLMessageDisconnect send would fail, Dispose must not throw (the socket close always runs).")]
    public void Dispose_WithBrokenPeer_DoesNotThrow()
    {
        (ServiceConnection connection, Socket server, Socket client) = CreatePair();

        // Construct the service BEFORE breaking the transport (the ctor touches the socket via SetTimeout).
        var dl = new DeviceLinkService(connection, backupDirectory: string.Empty, iosVersion: new Version(17, 0),
            logger: NullLogger.Instance);

        // Break the transport: the DLMessageDisconnect send will fault (IOException), but Dispose must
        // still complete and close the socket without surfacing an exception (unreachable-proof).
        server.Dispose();
        client.Dispose();

        // Must not throw.
        dl.Dispose();
    }

    [TestMethod]
    [Timeout(15000)]
    [DataRow(false, DisplayName = "Dispose")]
    [DataRow(true, DisplayName = "DisposeQuietly")]
    public async Task Dispose_MidUpload_ReleasesPartialFile(bool quietly)
    {
        string root = Path.Combine(Path.GetTempPath(), "dl-dispose-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            (ServiceConnection connection, Socket server, Socket _) = CreatePair();
            using ServiceConnection device = CreateServiceConnection(server, timeout: 5000);
            var dl = new DeviceLinkService(connection, root, new Version(17, 0), logger: NullLogger.Instance);
            var chunkWritten = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            dl.FileReceiving += (_, _) => chunkWritten.TrySetResult();
            Task<ResultCode> loop = dl.DlLoop(CancellationToken.None);

            await device.SendPlistAsync(new ArrayNode {
                new StringNode(DeviceLinkMessage.UploadFiles), new DictionaryNode(), new RealNode(0.5), new IntegerNode(100)
            }, PlistFormat.Binary);
            byte[] payload = [1, 2, 3, 4];
            await device.SendAsync(Frame(Name("device/partial"), Name("partial"), Int32(1 + payload.Length), [(byte)ResultCode.FileData], payload));
            await chunkWritten.Task;

            if (quietly) {
                dl.DisposeQuietly();
            }
            else {
                dl.Dispose();
            }
            try {
                await loop;
            }
            catch (Exception) {
            }

            string partial = Path.Combine(root, "partial");
            using (new FileStream(partial, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
            }
            File.Delete(partial);
            Assert.IsFalse(File.Exists(partial));
        }
        finally {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] Int32(int value)
    {
        byte[] bytes = new byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Name(string name)
    {
        byte[] utf8 = System.Text.Encoding.UTF8.GetBytes(name);
        return [.. Int32(utf8.Length), .. utf8];
    }

    private static byte[] Frame(params byte[][] parts) => [.. parts.SelectMany(p => p)];

    private static (ServiceConnection connection, Socket server, Socket client) CreatePair()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task<Socket> acceptTask = listener.AcceptSocketAsync();
        var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
        client.Connect(IPAddress.Loopback, port);
        Socket server = acceptTask.GetAwaiter().GetResult();

        ServiceConnection connection = CreateServiceConnection(client, timeout: 5000);
        return (connection, server, client);
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
