using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

[TestClass]
public class DeviceLinkHandlerReplyTests
{
    private string _root = string.Empty;

    [TestInitialize]
    public void CreateRoot()
    {
        _root = Path.Combine(Path.GetTempPath(), "dl-reply-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [TestCleanup]
    public void DeleteRoot() => Directory.Delete(_root, recursive: true);

    [TestMethod]
    [Timeout(15000)]
    public async Task PurgeDiskSpace_RepliesOnceWithFailedToPurge()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair);

        await InvokeHandler(dl, DeviceLinkMessage.PurgeDiskSpace,
            [new StringNode(DeviceLinkMessage.PurgeDiskSpace), new IntegerNode(0x80000000L), new IntegerNode(0)]);

        ArrayNode status = PropertyList.LoadFromByteArray(ReadFrame(pair.Server)).AsArrayNode();
        Assert.AreEqual("DLMessageStatusResponse", status[0].AsStringNode().Value);
        Assert.AreEqual(-1L, status[1].AsIntegerNode().SignedValue);
        Assert.AreEqual("DLMessagePurgeDiskSpace failed to purge", status[2].AsStringNode().Value);
        Assert.IsFalse(pair.Server.Poll(200_000, SelectMode.SelectRead), "PurgeDiskSpace must send exactly one response.");
    }

    [TestMethod]
    [Timeout(15000)]
    [DataRow("missing.bin", "missing", "No such file or directory.", -6L)]
    [DataRow("folder", "directory", "Is a directory.", -9L)]
    [DataRow("locked.bin", "locked", "Input/output error.", -11L)]
    public async Task DownloadFiles_ReportsTheMatchingErrno(string name, string kind, string expectedMessage, long expectedCode)
    {
        string path = Path.Combine(_root, name);
        FileStream? lockHolder = null;
        if (kind == "directory") {
            Directory.CreateDirectory(path);
        }
        else if (kind == "locked") {
            File.WriteAllBytes(path, [1, 2, 3]);
            lockHolder = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }

        try {
            using SocketPair pair = SocketPair.CreateConnected();
            using DeviceLinkService dl = CreateService(pair);

            await InvokeHandler(dl, DeviceLinkMessage.DownloadFiles,
                [new StringNode(DeviceLinkMessage.DownloadFiles), new ArrayNode { new StringNode(name) }]);

            Assert.AreEqual(name, Encoding.UTF8.GetString(ReadFrame(pair.Server)));
            byte[] fileFrame = ReadFrame(pair.Server);
            Assert.AreEqual((byte)ResultCode.LocalError, fileFrame[0]);
            Assert.AreEqual(expectedMessage, Encoding.UTF8.GetString(fileFrame, 1, fileFrame.Length - 1));
            Assert.AreEqual(0, ReadFrame(pair.Server).Length, "The file-transfer terminator must follow the per-file frame.");

            ArrayNode status = PropertyList.LoadFromByteArray(ReadFrame(pair.Server)).AsArrayNode();
            DictionaryNode fileError = status[3].AsDictionaryNode()[name].AsDictionaryNode();
            Assert.AreEqual(expectedCode, fileError["DLFileErrorCode"].AsIntegerNode().SignedValue);
            Assert.AreEqual(expectedMessage, fileError["DLFileErrorString"].AsStringNode().Value);
        }
        finally {
            lockHolder?.Dispose();
        }
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task DownloadFiles_StreamsAReadableFileThenSuccess()
    {
        File.WriteAllBytes(Path.Combine(_root, "ok.bin"), [1, 2, 3]);
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair);

        await InvokeHandler(dl, DeviceLinkMessage.DownloadFiles,
            [new StringNode(DeviceLinkMessage.DownloadFiles), new ArrayNode { new StringNode("ok.bin") }]);

        Assert.AreEqual("ok.bin", Encoding.UTF8.GetString(ReadFrame(pair.Server)));
        CollectionAssert.AreEqual(new byte[] { (byte)ResultCode.FileData, 1, 2, 3 }, ReadFrame(pair.Server));
        CollectionAssert.AreEqual(new byte[] { (byte)ResultCode.Success }, ReadFrame(pair.Server));
        Assert.AreEqual(0, ReadFrame(pair.Server).Length);
        ArrayNode status = PropertyList.LoadFromByteArray(ReadFrame(pair.Server)).AsArrayNode();
        Assert.AreEqual(0L, status[1].AsIntegerNode().SignedValue);
    }

    [TestMethod]
    [Timeout(15000)]
    [DataRow(new byte[] { (byte)ResultCode.LocalError }, DisplayName = "unexpected code")]
    [DataRow(new byte[] { (byte)ResultCode.FileData }, DisplayName = "zero-length FileData")]
    public async Task UploadFiles_UnexpectedFrameMidFile_ThrowsAndLeavesTheFileClosedAndUnappended(byte[] badFrame)
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair);
        pair.Server.Send([
            .. Frame(Encoding.UTF8.GetBytes("dev/a")), .. Frame(Encoding.UTF8.GetBytes("a.bin")),
            .. Frame([(byte)ResultCode.FileData, 1, 2, 3]), .. Frame(badFrame),
            .. Frame(Encoding.UTF8.GetBytes("dev/b")), .. Frame(Encoding.UTF8.GetBytes("b.bin")),
            .. Frame([(byte)ResultCode.FileData, 9, 9]), .. Frame([(byte)ResultCode.Success]),
            .. BigEndian(0)]);

        await Assert.ThrowsExactlyAsync<DeviceLinkException>(() => InvokeHandler(dl, DeviceLinkMessage.UploadFiles,
            [new StringNode(DeviceLinkMessage.UploadFiles), new DictionaryNode(), new IntegerNode(0), new IntegerNode(0)]));

        ArrayNode status = PropertyList.LoadFromByteArray(ReadFrame(pair.Server)).AsArrayNode();
        Assert.IsTrue(status[1].AsIntegerNode().SignedValue < 0, "A failed UploadFiles must reply with an error status.");
        Assert.IsFalse(pair.Server.Poll(200_000, SelectMode.SelectRead), "UploadFiles must send exactly one response.");
        CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(_root, "a.bin")));
        Assert.IsFalse(File.Exists(Path.Combine(_root, "b.bin")));
    }

    private static byte[] Frame(byte[] payload) => [.. BigEndian(payload.Length), .. payload];

    private static byte[] BigEndian(int value)
    {
        byte[] bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        return bytes;
    }

    private DeviceLinkService CreateService(SocketPair pair) =>
        new(CreateServiceConnection(pair.Client), _root, new Version(17, 0), logger: NullLogger.Instance);

    private static Task InvokeHandler(DeviceLinkService dl, string command, ArrayNode message)
    {
        var handlers = (Dictionary<string, Func<ArrayNode, CancellationToken, Task>>)typeof(DeviceLinkService)
            .GetProperty("DeviceLinkHandlers", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(dl)!;
        return handlers[command](message, CancellationToken.None);
    }

    private static byte[] ReadFrame(Socket socket)
    {
        byte[] length = ReadExactly(socket, 4);
        return ReadExactly(socket, BinaryPrimitives.ReadInt32BigEndian(length));
    }

    private static byte[] ReadExactly(Socket socket, int count)
    {
        byte[] buffer = new byte[count];
        int read = 0;
        while (read < count) {
            int n = socket.Receive(buffer, read, count - read, SocketFlags.None);
            if (n == 0) {
                throw new AssertFailedException("The connection closed before the expected bytes arrived.");
            }
            read += n;
        }
        return buffer;
    }

    private static ServiceConnection CreateServiceConnection(Socket connectedSocket)
    {
        ConstructorInfo ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(Netimobiledevice.Usbmuxd.UsbmuxdDevice)],
            modifiers: null)
            ?? throw new AssertFailedException("ServiceConnection(Socket, int, ILogger, UsbmuxdDevice?) constructor must exist for this test.");

        return (ServiceConnection)ctor.Invoke([connectedSocket, 5000, NullLogger.Instance, null]);
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
            return new SocketPair { Client = client, Server = acceptTask.GetAwaiter().GetResult() };
        }

        public void Dispose()
        {
            try { Client.Dispose(); } catch (SocketException) { }
            try { Server.Dispose(); } catch (SocketException) { }
        }
    }
}
