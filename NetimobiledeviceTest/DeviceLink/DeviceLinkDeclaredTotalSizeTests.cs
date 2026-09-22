using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// #3081: instrumentation for the DLMessageUploadFiles msg[3] value ("backupTotalSize").
///
/// Whether that value is a whole-backup byte total or a per-batch size is UNSETTLED. It is read fresh
/// on every <c>UploadFiles</c> invocation, and <c>DlLoop</c> dispatches that message many times per
/// session, so the variable alone cannot answer it — and the LogDebug that previously reported it sat
/// under a category floored at Warning, so no log has ever recorded a single value.
///
/// The recorder exists to let ONE real backup decide it: a constant value across many observations
/// means whole-backup; a varying one means per-batch. These tests pin the classification logic so the
/// eventual log line can be trusted as evidence. They do NOT assert which answer the device gives.
/// </summary>
[TestClass]
public class DeviceLinkDeclaredTotalSizeTests
{
    [TestMethod]
    [Description("A single observation records the value as both first and max, and is not yet varied.")]
    public void FirstObservation_SeedsFirstAndMax()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair.Client);

        dl.RecordDeclaredTotalSize(51_200_000_000);

        Assert.AreEqual(1, dl.DeclaredTotalSizeObservations);
        Assert.AreEqual(51_200_000_000, dl.FirstDeclaredTotalSize);
        Assert.AreEqual(51_200_000_000, dl.MaxDeclaredTotalSize);
        Assert.IsFalse(dl.DeclaredTotalSizeVaried,
            "One observation cannot establish variation.");
    }

    [TestMethod]
    [Description("A constant value across many invocations is the WHOLE-BACKUP signature: not varied.")]
    public void ConstantAcrossInvocations_IsNotVaried()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair.Client);

        for (int i = 0; i < 12; i++) {
            dl.RecordDeclaredTotalSize(51_200_000_000);
        }

        Assert.AreEqual(12, dl.DeclaredTotalSizeObservations);
        Assert.IsFalse(dl.DeclaredTotalSizeVaried,
            "A value that never changes across 12 UploadFiles messages is a whole-backup total.");
        Assert.AreEqual(dl.FirstDeclaredTotalSize, dl.MaxDeclaredTotalSize);
    }

    [TestMethod]
    [Description("A changing value is the PER-BATCH signature, which would refute using it as a denominator.")]
    public void VaryingAcrossInvocations_IsFlaggedVaried()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair.Client);

        dl.RecordDeclaredTotalSize(4_000_000);
        dl.RecordDeclaredTotalSize(17_100_000_000);
        dl.RecordDeclaredTotalSize(2_500_000);

        Assert.AreEqual(3, dl.DeclaredTotalSizeObservations);
        Assert.IsTrue(dl.DeclaredTotalSizeVaried,
            "A value that differs between messages is per-batch, not a whole-backup total.");
        Assert.AreEqual(4_000_000, dl.FirstDeclaredTotalSize);
        Assert.AreEqual(17_100_000_000, dl.MaxDeclaredTotalSize,
            "Max must survive a later SMALLER observation — it is the running high-water mark.");
    }

    [TestMethod]
    [Description("Nothing is recorded before the first UploadFiles message, so absence is distinguishable from zero.")]
    public void NoObservations_LeavesTheCountersZero()
    {
        using SocketPair pair = SocketPair.CreateConnected();
        using DeviceLinkService dl = CreateService(pair.Client);

        Assert.AreEqual(0, dl.DeclaredTotalSizeObservations);
        Assert.AreEqual(0, dl.FirstDeclaredTotalSize);
        Assert.AreEqual(0, dl.MaxDeclaredTotalSize);
        Assert.IsFalse(dl.DeclaredTotalSizeVaried);
    }

    private static DeviceLinkService CreateService(Socket connectedSocket)
        => new(CreateServiceConnection(connectedSocket, timeout: 5000),
            backupDirectory: string.Empty, iosVersion: new Version(17, 0), logger: NullLogger.Instance);

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
