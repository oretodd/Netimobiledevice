using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

[TestClass]
public class DeviceLinkFileOperationTests
{
    private string _root = string.Empty;

    [TestInitialize]
    public void Setup()
    {
        _root = Path.Combine(Path.GetTempPath(), "dl-fileops-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_root, recursive: true);

    [TestMethod]
    [Timeout(15000)]
    public async Task MoveItems_MissingSource_LeavesDestinationUnchanged()
    {
        File.WriteAllText(Path.Combine(_root, "dest"), "good");

        await RunAsync(MoveMessage("missing", "dest"));

        Assert.AreEqual("good", File.ReadAllText(Path.Combine(_root, "dest")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task MoveItems_DirectorySource_ReplacesDestinationWithContents()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "sub"));
        File.WriteAllText(Path.Combine(_root, "src", "sub", "a.txt"), "new");
        Directory.CreateDirectory(Path.Combine(_root, "dest"));
        File.WriteAllText(Path.Combine(_root, "dest", "stale.txt"), "old");

        await RunAsync(MoveMessage("src", "dest"));

        Assert.IsFalse(Directory.Exists(Path.Combine(_root, "src")));
        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "dest", "sub", "a.txt")));
        Assert.IsFalse(File.Exists(Path.Combine(_root, "dest", "stale.txt")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task MoveItems_FileSource_ReplacesDestination()
    {
        File.WriteAllText(Path.Combine(_root, "src"), "new");
        File.WriteAllText(Path.Combine(_root, "dest"), "old");

        await RunAsync(MoveMessage("src", "dest"));

        Assert.IsFalse(File.Exists(Path.Combine(_root, "src")));
        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "dest")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task MoveItems_DestinationIsSourceWithDifferentCase_KeepsContents()
    {
        File.WriteAllText(Path.Combine(_root, "file"), "keep");
        Directory.CreateDirectory(Path.Combine(_root, "dir"));
        File.WriteAllText(Path.Combine(_root, "dir", "a.txt"), "keep");

        await RunAsync(MoveMessage("file", "FILE"));
        await RunAsync(MoveMessage("dir", "DIR"));

        Assert.AreEqual("keep", File.ReadAllText(Path.Combine(_root, "FILE")));
        Assert.AreEqual("keep", File.ReadAllText(Path.Combine(_root, "DIR", "a.txt")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task CopyItem_FileSource_ReplacesDestination()
    {
        File.WriteAllText(Path.Combine(_root, "src"), "new");
        File.WriteAllText(Path.Combine(_root, "dest"), "old");

        await RunAsync([new StringNode(DeviceLinkMessage.CopyItem), new StringNode("src"), new StringNode("dest")]);

        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "src")));
        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "dest")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task CopyItem_DestinationIsSource_KeepsContents()
    {
        File.WriteAllText(Path.Combine(_root, "file"), "keep");

        await RunAsync([new StringNode(DeviceLinkMessage.CopyItem), new StringNode("file"), new StringNode("file")]);

        Assert.AreEqual("keep", File.ReadAllText(Path.Combine(_root, "file")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task CopyItem_DirectorySource_ReplacesDestinationWithCopy()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "sub"));
        File.WriteAllText(Path.Combine(_root, "src", "sub", "a.txt"), "new");
        File.WriteAllText(Path.Combine(_root, "dest"), "old");

        await RunAsync([new StringNode(DeviceLinkMessage.CopyItem), new StringNode("src"), new StringNode("dest")]);

        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "src", "sub", "a.txt")));
        Assert.AreEqual("new", File.ReadAllText(Path.Combine(_root, "dest", "sub", "a.txt")));
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task CopyItem_MissingSource_LeavesDestinationUnchanged()
    {
        File.WriteAllText(Path.Combine(_root, "dest"), "good");

        await RunAsync([new StringNode(DeviceLinkMessage.CopyItem), new StringNode("missing"), new StringNode("dest")]);

        Assert.AreEqual("good", File.ReadAllText(Path.Combine(_root, "dest")));
    }

    private static ArrayNode MoveMessage(string source, string dest) => [
        new StringNode(DeviceLinkMessage.MoveItems),
        new DictionaryNode { { source, new StringNode(dest) } },
        new DictionaryNode(),
        new RealNode(0.5)
    ];

    // Plays the device: sends one request, expects exactly one success status, then ends the session.
    private async Task RunAsync(ArrayNode request)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task<Socket> accept = listener.AcceptSocketAsync();
        using var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using Socket server = await accept;

        ServiceConnection device = CreateServiceConnection(server);
        using var dl = new DeviceLinkService(CreateServiceConnection(client), _root, new Version(17, 0),
            logger: NullLogger.Instance);
        Task<ResultCode> loop = dl.DlLoop(CancellationToken.None);

        await device.SendPlistAsync(request, PlistFormat.Binary);
        ArrayNode status = (await device.ReceivePlistAsync())!.AsArrayNode();
        Assert.AreEqual("DLMessageStatusResponse", status[0].AsStringNode().Value);
        Assert.AreEqual(0UL, status[1].AsIntegerNode().Value);

        await device.SendPlistAsync(new ArrayNode {
            new StringNode(DeviceLinkMessage.ProcessMessage),
            new DictionaryNode { { "ErrorCode", new IntegerNode(0) } }
        }, PlistFormat.Binary);

        Assert.AreEqual(ResultCode.Success, await loop);
        Assert.AreEqual(0, server.Available, "The request must be answered by exactly one status response.");
    }

    private static ServiceConnection CreateServiceConnection(Socket socket)
    {
        ConstructorInfo ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(Netimobiledevice.Usbmuxd.UsbmuxdDevice)],
            modifiers: null)!;
        return (ServiceConnection)ctor.Invoke([socket, 5000, NullLogger.Instance, null]);
    }
}
