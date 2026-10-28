using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.Backup;

[TestClass]
public class CancelBackupTeardownTests
{
    private const string Udid = "00008030-TEST";

    [TestMethod]
    [Timeout(15000)]
    public async Task SuccessfulBackup_SendsNoCancelBackup()
    {
        string? first = await RunTeardownAsync(ResultCode.Success, quietAbandon: false);

        Assert.AreEqual("Marker", first);
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task QuietAbandon_SendsNoCancelBackup()
    {
        string? first = await RunTeardownAsync(result: null, quietAbandon: true);

        Assert.AreEqual("Marker", first);
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task FailedBackup_SendsCancelBackup()
    {
        string? first = await RunTeardownAsync(result: null, quietAbandon: false);

        Assert.AreEqual("CancelBackup", first);
    }

    [TestMethod]
    [Timeout(15000)]
    public async Task HostCancelledBackup_SendsCancelBackup()
    {
        string? first = await RunTeardownAsync(ResultCode.Skipped, quietAbandon: false);

        Assert.AreEqual("CancelBackup", first);
    }

    // Runs the teardown, then sends a marker; returns the MessageName of the first ProcessMessage the device sees.
    private static async Task<string?> RunTeardownAsync(ResultCode? result, bool quietAbandon)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task<Socket> accept = listener.AcceptSocketAsync();
        using var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using Socket server = await accept;

        ServiceConnection device = CreateServiceConnection(server);
        using var dl = new DeviceLinkService(CreateServiceConnection(client), string.Empty, new Version(17, 0),
            logger: NullLogger.Instance);

        await Mobilebackup2Service.CancelUnfinishedBackupAsync(dl, Udid, result, quietAbandon, NullLogger.Instance);
        await dl.SendProcessMessage(new DictionaryNode { { "MessageName", new StringNode("Marker") } }, CancellationToken.None);

        ArrayNode received = (await device.ReceivePlistAsync())!.AsArrayNode();
        Assert.AreEqual(DeviceLinkMessage.ProcessMessage, received[0].AsStringNode().Value);
        return received[1].AsDictionaryNode()["MessageName"].AsStringNode().Value;
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
