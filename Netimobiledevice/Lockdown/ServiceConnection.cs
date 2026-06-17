using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.EndianBitConversion;
using Netimobiledevice.Plist;
using Netimobiledevice.Usbmuxd;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Lockdown;

/// <summary>
/// A wrapper for usbmux tcp-relay connections
/// </summary>
public class ServiceConnection : IDisposable {
    private const int MAX_READ_SIZE = 32768;

    /// <summary>
    /// The internal logger
    /// </summary>
    private readonly ILogger _logger;
    /// <summary>
    /// The initial stream used for the ServiceConnection until the SSL stream starts, unless you specifically need to use this stream
    /// you should use the Stream property instead
    /// </summary>
    private readonly NetworkStream _networkStream;
    /// <summary>
    /// The main stream once SSL is established, unless you specifically need to use this stream you should use the Stream 
    /// property instead
    /// </summary>
    private SslStream? _sslStream;

    public UsbmuxdDevice? MuxDevice { get; private set; }

    public bool IsConnected {
        get {
            return _networkStream.Socket.Connected;
        }
    }

    public Stream Stream => _sslStream != null ? _sslStream : _networkStream;

    private ServiceConnection(Socket sock, ILogger logger, UsbmuxdDevice? muxDevice = null) {
        _logger = logger;
        _networkStream = new NetworkStream(sock, true);

        // Usbmux connections contain additional information associated with the current connection
        MuxDevice = muxDevice;
    }

    /// <summary>
    /// Apply the keepalive budget shared by every relay socket (usbmux-over-USB and TCP-over-WiFi alike).
    /// Both transports carry the same multiplexed device data channel, so both must outlast the
    /// multi-minute heads-down bursts iOS produces while servicing it — otherwise the local TCP stack
    /// aborts a healthy relay socket and the bulk read throws IOException(SocketException 10053/10054).
    /// Budget ~= 120 + 10*30 = ~7 min, kept under DeviceLinkService's 10-min read timeout. (#1857)
    /// </summary>
    private static void ConfigureKeepAlive(Socket sock) {
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 120);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 30);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 10);
    }

    /// <summary>
    /// Hard ceiling on a TCP-over-WiFi connect. A bare <c>Socket.Connect</c> has NO connect timeout, so a
    /// secondary lockdown-service connect to a WiFi device whose network socket has gone idle (Apple drops
    /// the mobdev2 TCP relay after ~1-3 min of inactivity) blocks the calling thread for the OS default —
    /// tens of seconds to effectively forever. ScribeHold opens these secondary connects synchronously
    /// from the backup worker (BackupKeepSet/Mobilebackup2Service -> StartLockdownService), so an unbounded
    /// connect wedges the whole backup in Backup_Initializing with no passcode and no progress (#1926). The
    /// primary lockdown connect is already bounded by WiFiLockdownConnectionFactory; this bounds every
    /// SUBSEQUENT per-service TCP connect the same way so a stalled endpoint fails fast and loud instead.
    /// </summary>
    private static readonly TimeSpan TcpConnectTimeout = TimeSpan.FromSeconds(10);

    private static Socket ConnectTcpBounded(IPAddress ip, ushort port) {
        Socket sock = new Socket(SocketType.Stream, ProtocolType.IP);
        try {
            // ConnectAsync + a timeout gives the bounded connect that Socket.Connect lacks. On timeout the
            // socket is disposed (cancelling the in-flight connect) and a SocketException(TimedOut) is
            // thrown — the same shape callers already handle as a failed connect.
            using var cts = new CancellationTokenSource(TcpConnectTimeout);
            sock.ConnectAsync(ip, port, cts.Token).AsTask().GetAwaiter().GetResult();
            return sock;
        }
        catch (OperationCanceledException) {
            sock.Dispose();
            throw new SocketException((int) SocketError.TimedOut);
        }
        catch {
            sock.Dispose();
            throw;
        }
    }

    internal static ServiceConnection CreateUsingTcp(string hostname, ushort port, ILogger? logger = null) {
        IPAddress ip = IPAddress.Parse(hostname);
        Socket sock = ConnectTcpBounded(ip, port);
        ConfigureKeepAlive(sock);
        return new ServiceConnection(sock, logger ?? NullLogger.Instance);
    }

    internal static async Task<ServiceConnection> CreateUsingTcpAsync(string hostname, ushort port, ILogger? logger = null) {
        IPAddress ip = IPAddress.Parse(hostname);
        Socket sock = new Socket(SocketType.Stream, ProtocolType.IP);
        try {
            using var cts = new CancellationTokenSource(TcpConnectTimeout);
            await sock.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) {
            sock.Dispose();
            throw new SocketException((int) SocketError.TimedOut);
        }
        catch {
            sock.Dispose();
            throw;
        }
        ConfigureKeepAlive(sock);
        return new ServiceConnection(sock, logger ?? NullLogger.Instance);
    }

    internal static ServiceConnection CreateUsingUsbmux(string udid, ushort port, UsbmuxdConnectionType? connectionType = null, string usbmuxAddress = "", ILogger? logger = null) {
        UsbmuxdDevice? targetDevice = Usbmux.GetDevice(udid, connectionType: connectionType, usbmuxAddress: usbmuxAddress);
        if (targetDevice == null) {
            if (!string.IsNullOrEmpty(udid)) {
                throw new ConnectionFailedException();
            }
            throw new NoDeviceConnectedException();
        }
        Socket sock = targetDevice.Connect(port, usbmuxAddress: usbmuxAddress, logger);
        ConfigureKeepAlive(sock);
        return new ServiceConnection(sock, logger ?? NullLogger.Instance, targetDevice);
    }

    internal static async Task<ServiceConnection> CreateUsingUsbmuxAsync(string udid, ushort port, UsbmuxdConnectionType? connectionType = null, string usbmuxAddress = "", ILogger? logger = null) {
        UsbmuxdDevice? targetDevice = Usbmux.GetDevice(udid, connectionType: connectionType, usbmuxAddress: usbmuxAddress);
        if (targetDevice == null) {
            if (!string.IsNullOrEmpty(udid)) {
                throw new ConnectionFailedException();
            }
            throw new NoDeviceConnectedException();
        }
        Socket sock = await targetDevice.ConnectAsync(port, usbmuxAddress: usbmuxAddress, logger).ConfigureAwait(false);
        ConfigureKeepAlive(sock);
        return new ServiceConnection(sock, logger ?? NullLogger.Instance, targetDevice);
    }

    private bool UserCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) {
        return true;
    }

    public void Close() {
        Stream.Close();
    }

    public void Dispose() {
        Close();
        Stream.Dispose();
        GC.SuppressFinalize(this);
    }

    public byte[] Receive(int length = 4096) {
        if (length <= 0) {
            return [];
        }
        byte[] buffer = new byte[length];

        int totalBytesRead = 0;
        while (totalBytesRead < length) {
            int remainingSize = length - totalBytesRead;
            int readSize = remainingSize;
            if (remainingSize > MAX_READ_SIZE) {
                readSize = MAX_READ_SIZE;
            }

            int bytesRead = Stream.Read(buffer, totalBytesRead, readSize);
            if (bytesRead == 0) {
                _logger.LogError("Read zero bytes so the connection has been broken");
                break;
            }
            totalBytesRead += bytesRead;
        }

        if (totalBytesRead < buffer.Length) {
            return [.. buffer.Take(totalBytesRead)];
        }
        return buffer;
    }

    public async Task<byte[]> ReceiveAsync(int length, CancellationToken cancellationToken) {
        if (length <= 0) {
            return [];
        }
        byte[] buffer = new byte[length];

        int totalBytesRead = 0;
        while (totalBytesRead < length) {
            int remainingSize = length - totalBytesRead;
            int readSize = remainingSize;
            if (remainingSize > MAX_READ_SIZE) {
                readSize = MAX_READ_SIZE;
            }

            int bytesRead;
            if (Stream.ReadTimeout != -1) {
                CancellationTokenSource localTaskComplete = new CancellationTokenSource(Stream.ReadTimeout);
                CancellationTokenSource linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(localTaskComplete.Token, cancellationToken);
                using (linkedCancellationTokenSource) {
                    try {
                        bytesRead = await Stream.ReadAsync(buffer.AsMemory(totalBytesRead, readSize), linkedCancellationTokenSource.Token).ConfigureAwait(false);
                        if (bytesRead == 0) {
                            _logger.LogError("Read zero bytes so the connection has been broken");
                            break;
                        }
                    }
                    catch (OperationCanceledException) {
                        if (localTaskComplete.IsCancellationRequested) {
                            throw new TimeoutException("Timeout waiting for message from service");
                        }
                        throw;
                    }
                }
            }
            else {
                bytesRead = await Stream.ReadAsync(buffer.AsMemory(totalBytesRead, readSize), cancellationToken).ConfigureAwait(false);
            }

            totalBytesRead += bytesRead;
        }

        if (totalBytesRead < buffer.Length) {
            return [.. buffer.Take(totalBytesRead)];
        }
        return buffer;
    }

    public PropertyNode? ReceivePlist() {
        byte[] plistBytes = ReceivePrefixed();
        if (plistBytes.Length == 0) {
            return null;
        }
        return PropertyList.LoadFromByteArray(plistBytes);
    }

    public async Task<PropertyNode?> ReceivePlistAsync(CancellationToken cancellationToken) {
        byte[] plistBytes = await ReceivePrefixedAsync(cancellationToken).ConfigureAwait(false);
        if (plistBytes.Length == 0) {
            return null;
        }
        return await PropertyList.LoadFromByteArrayAsync(plistBytes).ConfigureAwait(false);
    }

    /// <summary>
    /// Receive a data block prefixed with a u32 length field
    /// </summary>
    /// <returns>The data without the u32 field length as a byte array</returns>
    public byte[] ReceivePrefixed() {
        byte[] sizeBytes = Receive(4);
        if (sizeBytes.Length != 4) {
            return [];
        }

        int size = EndianBitConverter.BigEndian.ToInt32(sizeBytes, 0);
        return Receive(size);
    }

    /// <summary>
    /// Receive a data block prefixed with a u32 length field
    /// </summary>
    /// <returns>The data without the u32 field length as a byte array</returns>
    public async Task<byte[]> ReceivePrefixedAsync(CancellationToken cancellationToken = default) {
        byte[] sizeBytes = await ReceiveAsync(4, cancellationToken).ConfigureAwait(false);
        if (sizeBytes.Length != 4) {
            return [];
        }

        int size = EndianBitConverter.BigEndian.ToInt32(sizeBytes, 0);
        return await ReceiveAsync(size, cancellationToken).ConfigureAwait(false);
    }

    public void Send(ReadOnlySpan<byte> data) {
        Stream.Write(data);
    }

    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken) {
        await Stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
    }

    public void SendPlist(PropertyNode data, PlistFormat format = PlistFormat.Xml) {
        byte[] plistBytes = PropertyList.SaveAsByteArray(data, format);
        byte[] lengthBytes = BitConverter.GetBytes(EndianBitConverter.BigEndian.ToUInt32(BitConverter.GetBytes(plistBytes.Length), 0));

        Send(lengthBytes);
        Send(plistBytes);
    }

    public async Task SendPlistAsync(PropertyNode data, PlistFormat format = PlistFormat.Xml, CancellationToken cancellationToken = default) {
        byte[] plistBytes = PropertyList.SaveAsByteArray(data, format);
        byte[] lengthBytes = BitConverter.GetBytes(EndianBitConverter.BigEndian.ToUInt32(BitConverter.GetBytes(plistBytes.Length), 0));

        await SendAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
        await SendAsync(plistBytes, cancellationToken).ConfigureAwait(false);
    }

    public PropertyNode? SendReceivePlist(PropertyNode data) {
        SendPlist(data);
        int rt = SafeTimeout(() => Stream.ReadTimeout);
        _logger.LogInformation("[mb2-diag] SendReceivePlist: sent request, blocking on synchronous read (ReadTimeout={ReadTimeout}ms, ssl={Ssl})", rt, _sslStream != null);
        PropertyNode? result = ReceivePlist();
        _logger.LogInformation("[mb2-diag] SendReceivePlist: read completed");
        return result;
    }

    public async Task<PropertyNode?> SendReceivePlistAsync(PropertyNode data, CancellationToken cancellationToken) {
        await SendPlistAsync(data, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await ReceivePlistAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Set a value in milliseconds, that determines how long the service connection will attempt to read/write for before timing out
    /// </summary>
    /// <param name="timeout">A value in milliseconds that detemines how long the service connection will wait before timing out</param>
    public void SetTimeout(int timeout = -1) {
        Stream.ReadTimeout = timeout;
        Stream.WriteTimeout = timeout;
    }

    /// <summary>
    /// Hard ceiling on the synchronous SSL handshake (<see cref="SslStream.AuthenticateAsClient(string)"/>).
    /// The handshake reads from the underlying socket with NO timeout of its own, so when a WiFi device
    /// accepts the secondary mobilebackup2 service TCP connection but never completes the TLS handshake
    /// (its lockdown relay went idle, or it is mid-reauthorising the wireless session), the backup worker
    /// thread blocks here FOREVER and the backup wedges in Backup_Initializing with no passcode and no
    /// progress — the connect is bounded but the handshake was not (ScribeHold #1926, deeper layer). A
    /// finite handshake deadline makes a stalled handshake throw so the attempt fails fast and retries.
    /// </summary>
    private static readonly TimeSpan SslHandshakeTimeout = TimeSpan.FromSeconds(30);

    public bool StartSsl(X509Certificate2 certificate) {
        if (_networkStream == null) {
            throw new InvalidOperationException("Network stream is null");
        }
        // Carry any read/write timeout configured on the pre-SSL network stream forward to the SSL stream:
        // SslStream defaults to an infinite timeout and does NOT inherit the inner stream's, so a control
        // channel that set a finite SetTimeout before the handshake would silently lose it once SSL starts
        // and could then block forever on a stalled read (ScribeHold #1926). -1 (infinite) is preserved as
        // -1, so the bulk data channel is unaffected.
        int readTimeout = SafeTimeout(() => _networkStream.ReadTimeout);
        int writeTimeout = SafeTimeout(() => _networkStream.WriteTimeout);
        _networkStream.Flush();

        _sslStream = new SslStream(_networkStream, true, UserCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption);
        try {
            SslClientAuthenticationOptions authOptions = new() {
                TargetHost = string.Empty,
                ClientCertificates = [certificate],
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };
            // Bound the handshake: AuthenticateAsClient has no timeout, so use the cancellable async
            // overload with a deadline and block on it. On timeout the socket read is cancelled and we
            // surface it as a failed handshake (the same shape callers already treat as a pairing/connect
            // failure), instead of hanging the backup thread indefinitely.
            using var handshakeCts = new CancellationTokenSource(SslHandshakeTimeout);
            _sslStream.AuthenticateAsClientAsync(authOptions, handshakeCts.Token).GetAwaiter().GetResult();
        }
        catch (AuthenticationException ex) {
            _logger.LogError(ex, "SSL authentication failed");
            return false;
        }
        catch (OperationCanceledException) {
            _logger.LogError("SSL handshake timed out after {TimeoutSeconds}s on the service connection", SslHandshakeTimeout.TotalSeconds);
            return false;
        }

        if (readTimeout != Timeout.Infinite) {
            _sslStream.ReadTimeout = readTimeout;
        }
        if (writeTimeout != Timeout.Infinite) {
            _sslStream.WriteTimeout = writeTimeout;
        }
        return true;
    }

    /// <summary>Read a stream timeout property defensively (NetworkStream throws if no timeout is set).</summary>
    private static int SafeTimeout(Func<int> get) {
        try {
            return get();
        }
        catch {
            return Timeout.Infinite;
        }
    }

    public async Task<bool> StartSslAsync(X509Certificate2 certificate) {
        if (_networkStream == null) {
            throw new InvalidOperationException("Network stream is null");
        }
        await _networkStream.FlushAsync().ConfigureAwait(false);

        _sslStream = new SslStream(_networkStream, true, UserCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption);
        try {
            // TLS v1.2 is supported since iOS 5 so we should specify this as a minimum.
            // Bound the handshake symmetrically with the synchronous StartSsl (#1926): an unbounded
            // handshake on a fresh per-service WiFi socket wedges the backup forever. Any caller that
            // switches to the async StartLockdownService path must get the same protection.
            SslClientAuthenticationOptions authOptions = new() {
                TargetHost = string.Empty,
                ClientCertificates = [certificate],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };
            using var handshakeCts = new CancellationTokenSource(SslHandshakeTimeout);
            await _sslStream.AuthenticateAsClientAsync(authOptions, handshakeCts.Token).ConfigureAwait(false);
        }
        catch (AuthenticationException ex) {
            _logger.LogError(ex, "SSL authentication failed");
            return false;
        }
        catch (OperationCanceledException) {
            _logger.LogError("SSL handshake timed out after {TimeoutSeconds}s on the service connection", SslHandshakeTimeout.TotalSeconds);
            return false;
        }

        return true;
    }
}
