using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;
using Netimobiledevice.Usbmuxd;

namespace NetimobiledeviceTest.Lockdown.Pairing;

[TestClass]
public class PairRetryKeyGenerationTests
{
    [TestMethod]
    [Timeout(30000)]
    public void PendingTrustDialog_ResendsThePairRequestWithOneHostKey()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
        client.Connect((IPEndPoint)listener.LocalEndpoint);
        using Socket server = listener.AcceptSocket();
        List<string> hostCertificates = [];
        Thread lockdownd = new(() => ServeLockdown(CreateServiceConnection(server), hostCertificates)) { IsBackground = true };
        lockdownd.Start();

        Assert.ThrowsExactly<FatalPairingException>(() =>
            TcpLockdownClient.Create(CreateServiceConnection(client), localHostname: "test-host", autopair: true, pairTimeout: 1));

        lock (hostCertificates) {
            Assert.IsTrue(hostCertificates.Count >= 3, $"expected several pending re-sends, saw {hostCertificates.Count}");
            Assert.AreEqual(1, hostCertificates.Distinct().Count(), "every re-send must carry the same generated host key");
        }
        client.Dispose();
    }

    private static void ServeLockdown(ServiceConnection connection, List<string> hostCertificates)
    {
        using RSA deviceKey = RSA.Create(2048);
        byte[] devicePublicKey = Encoding.UTF8.GetBytes(deviceKey.ExportRSAPublicKeyPem());
        try {
            while (connection.ReceivePlist() is DictionaryNode request) {
                string name = request["Request"].AsStringNode().Value;
                DictionaryNode reply = new() { { "Request", new StringNode(name) } };
                switch (name) {
                    case "QueryType":
                        reply.Add("Type", new StringNode("com.apple.mobile.lockdown"));
                        break;
                    case "GetValue" when request.ContainsKey("Key"):
                        reply.Add("Value", request["Key"].AsStringNode().Value == "DevicePublicKey" ? new DataNode(devicePublicKey) : new StringNode("00:11:22:33:44:55"));
                        break;
                    case "GetValue":
                        reply.Add("Value", new DictionaryNode {
                            { "ProductType", new StringNode("iPhone15,2") },
                            { "UniqueDeviceID", new StringNode("00008120-001C45942612601E") },
                            { "DevicePublicKey", new DataNode(devicePublicKey) },
                        });
                        break;
                    case "Pair":
                        lock (hostCertificates) {
                            hostCertificates.Add(Convert.ToBase64String(request["PairRecord"].AsDictionaryNode()["HostCertificate"].AsDataNode().Value));
                        }
                        reply.Add("Error", new StringNode("PairingDialogResponsePending"));
                        break;
                }
                connection.SendPlist(reply);
            }
        }
        catch (Exception) {
        }
    }

    private static ServiceConnection CreateServiceConnection(Socket connectedSocket)
    {
        ConstructorInfo ctor = typeof(ServiceConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: [typeof(Socket), typeof(int), typeof(Microsoft.Extensions.Logging.ILogger), typeof(UsbmuxdDevice)],
            modifiers: null)
            ?? throw new AssertFailedException("ServiceConnection(Socket, int, ILogger, UsbmuxdDevice?) constructor must exist for this test.");
        return (ServiceConnection)ctor.Invoke([connectedSocket, 10_000, NullLogger.Instance, null]);
    }
}
