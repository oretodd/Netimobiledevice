using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.DeviceLink;
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
    /// you should use the Stream property instead.
    /// </summary>
    private readonly NetworkStream _networkStream;
    /// <summary>
    /// The main stream once SSL is established, unless you specifically need to use this stream you should use the Stream
    /// property instead
    /// </summary>
    private SslStream? _sslStream;
    private int _timeout = Timeout.Infinite;

    /// <summary>
    /// ScribeHold fork (#2182): the transport-timeout policy this connection delegates to for the
    /// keepalive budget, the SSL-handshake watchdog bound, and (read by Task 1) the DlLoop
    /// inter-message silence bound. Defaults to <see cref="TransportTimeoutPolicy.UsbTight"/> so a
    /// standalone submodule consumer is safe; the hosting ScribeHold.Service overrides the concrete
    /// thresholds from <c>BackupConfiguration</c> via <see cref="TimeoutPolicy"/>.
    /// </summary>
    private TransportTimeoutPolicy _timeoutPolicy = TransportTimeoutPolicy.UsbTight;

    // ScribeHold fork (#2077): cumulative count of payload bytes the HOST has written on this
    // connection. At the version-exchange FIN the dump reports this so a wedge proves whether the
    // host sent ANYTHING before the device FIN'd (DeviceLink has the device speak first, so a healthy
    // flow has 0 host bytes before the first read — a non-zero count would be a stray host write).
    private long _bytesSent;
    // ScribeHold fork (#2077): when true, a 0-byte / short read at the version-exchange step may hex
    // dump the decrypted bytes it returned. The window is opened by DeviceLinkService.VersionExchange
    // and closed (in a finally) the moment version exchange ends, BEFORE the transfer phase. The same
    // SSL stream later carries the backup transfer (user message content); gating the hex dump on this
    // flag makes it structurally impossible to dump that content — the safety bound is in code, not
    // discipline. Default false: nothing dumps unless a version exchange explicitly armed it.
    private bool _versionExchangeWindow;

    public UsbmuxdDevice? MuxDevice { get; private set; }

    public bool IsConnected {
        get {
            return _networkStream.Socket.Connected;
        }
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-B): a passive, non-destructive transport health check. Returns
    /// <c>true</c> when the peer looks alive and <c>false</c> when the socket is a dead peer (a readable
    /// socket with zero bytes available is a received FIN/EOF; a socket error condition is an RST). Used
    /// when the generous <c>Preparing</c> silence bound trips: if the transport is healthy the device is
    /// still building its on-device manifest diff, so the DlLoop keeps waiting instead of tearing the
    /// session down. This reads NO application bytes — it only polls socket state — so it can never
    /// disturb the in-flight protocol. Best-effort and exception-safe: on any probe error it reports
    /// unhealthy (fail-safe toward teardown) rather than throwing into the loop.
    /// </summary>
    /// <returns><c>true</c> if the transport looks healthy; <c>false</c> if it is a dead peer.</returns>
    public bool IsTransportHealthy() {
        try {
            Socket socket = _networkStream.Socket;
            if (!socket.Connected) {
                return false;
            }
            // A received RST surfaces as an error condition.
            if (socket.Poll(0, SelectMode.SelectError)) {
                return false;
            }
            // Readable with nothing available, when no read is outstanding, is a peer FIN/EOF (dead peer).
            // Readable WITH bytes available, or not-readable, are both healthy (data pending, or simply
            // quiet while the device diffs). We treat only the readable-with-zero-available case as dead.
            if (socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0) {
                return false;
            }
            return true;
        }
        catch (ObjectDisposedException) {
            return false;
        }
        catch (SocketException) {
            return false;
        }
    }

    public Stream Stream => _sslStream != null ? _sslStream : _networkStream;

    /// <summary>
    /// ScribeHold fork (#2182): the transport-timeout policy this connection delegates to (keepalive
    /// budget, SSL-handshake watchdog bound, DlLoop inter-message silence bound). Defaults to
    /// <see cref="TransportTimeoutPolicy.UsbTight"/>. The hosting ScribeHold.Service assigns a policy
    /// derived from <c>BackupConfiguration</c> (Task 3) so USB is tight and WiFi stays loose; a
    /// standalone consumer inherits the USB-tight default. There are no inline "USB vs WiFi" branches
    /// in this class -- every transport-sensitive bound comes from the held policy.
    /// </summary>
    public TransportTimeoutPolicy TimeoutPolicy {
        get => _timeoutPolicy;
        set => _timeoutPolicy = value ?? throw new ArgumentNullException(nameof(value));
    }

    private ServiceConnection(Socket sock, int timeout, ILogger logger, UsbmuxdDevice? muxDevice = null) {
        _logger = logger;
        _timeout = timeout;
        _networkStream = new NetworkStream(sock, true) {
            ReadTimeout = _timeout,
            WriteTimeout = _timeout
        };

        // Usbmux connections contain additional information associated with the current connection
        MuxDevice = muxDevice;
    }

    internal static ServiceConnection CreateUsingTcp(string hostname, ushort port, int timeout = 10_000, ILogger? logger = null) {
        IPAddress ip = IPAddress.Parse(hostname);
        Socket sock = new Socket(SocketType.Stream, ProtocolType.IP);
        sock.Connect(ip, port);
        return new ServiceConnection(sock, timeout, logger ?? NullLogger.Instance);
    }

    internal static async Task<ServiceConnection> CreateUsingTcpAsync(string hostname, ushort port, int timeout = 10_000, ILogger? logger = null) {
        IPAddress ip = IPAddress.Parse(hostname);
        Socket sock = new Socket(SocketType.Stream, ProtocolType.IP);

        using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeout))) {
            try {
                await sock.ConnectAsync(ip, port).ConfigureAwait(false);
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

        return new ServiceConnection(sock, timeout, logger ?? NullLogger.Instance);
    }

    internal static ServiceConnection CreateUsingUsbmux(string udid, ushort port, UsbmuxdConnectionType? connectionType = null, string usbmuxAddress = "", int timeout = 10_000, ILogger? logger = null) {
        UsbmuxdDevice? targetDevice = Usbmux.GetDevice(udid, connectionType: connectionType, usbmuxAddress: usbmuxAddress);
        if (targetDevice == null) {
            if (!string.IsNullOrEmpty(udid)) {
                throw new ConnectionFailedException();
            }
            throw new NoDeviceConnectedException();
        }
        Socket sock = targetDevice.Connect(port, usbmuxAddress: usbmuxAddress, logger);
        // ScribeHold fork (#1857/#2182): keepalive budget must outlast the multi-minute heads-down
        // bursts usbmuxd produces while servicing the multiplexed device data channel — otherwise the
        // local TCP stack aborts a healthy relay socket and the bulk read throws IOException(10053/
        // 10054). The USB-tight budget (~120 + 10*30 = ~7 min, kept under DeviceLinkService's 10-min
        // read timeout) now comes from the transport policy rather than inline literals.
        ApplyKeepAlive(sock, TransportTimeoutPolicy.UsbTight);
        return new ServiceConnection(sock, timeout, logger ?? NullLogger.Instance, targetDevice);
    }

    internal static async Task<ServiceConnection> CreateUsingUsbmuxAsync(string udid, ushort port, UsbmuxdConnectionType? connectionType = null, string usbmuxAddress = "", int timeout = 10_000, ILogger? logger = null) {
        UsbmuxdDevice? targetDevice = Usbmux.GetDevice(udid, connectionType: connectionType, usbmuxAddress: usbmuxAddress);
        if (targetDevice == null) {
            if (!string.IsNullOrEmpty(udid)) {
                throw new ConnectionFailedException();
            }
            throw new NoDeviceConnectedException();
        }
        Socket sock = await targetDevice.ConnectAsync(port, usbmuxAddress: usbmuxAddress, logger).ConfigureAwait(false);
        // ScribeHold fork (#1857/#2182): see CreateUsingUsbmux — the USB-tight keepalive budget comes
        // from the transport policy so there is one source of truth for the #1857 budget.
        ApplyKeepAlive(sock, TransportTimeoutPolicy.UsbTight);
        return new ServiceConnection(sock, timeout, logger ?? NullLogger.Instance, targetDevice);
    }

    /// <summary>
    /// ScribeHold fork (#2182): apply the transport policy's TCP keepalive budget (#1857) to a usbmux
    /// relay socket. Delegating to the policy keeps the keepalive Time/Interval/RetryCount in exactly
    /// one place -- the <see cref="TransportTimeoutPolicy"/> -- instead of inline literals duplicated
    /// across the sync/async factories.
    /// </summary>
    private static void ApplyKeepAlive(Socket sock, TransportTimeoutPolicy policy) {
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, policy.KeepAliveTimeSec);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, policy.KeepAliveIntervalSec);
        sock.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, policy.KeepAliveRetryCount);
    }

    private bool UserCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) {
        return true;
    }

    public void Close() {
        // ScribeHold fork (#2197, P0-C): a REAL socket close so the device gets a deterministic TCP FIN.
        // The SslStream was constructed with leaveInnerStreamOpen:true, so disposing IT alone never closes
        // the socket-owning _networkStream — the prior `Stream.Close()` left the socket half-open (no FIN),
        // and the device got no release signal. Now we: (1) best-effort TLS close_notify (SslStream
        // .ShutdownAsync) under a short ~2s bound so a wedged peer can't hang the close, (2) dispose the
        // SslStream, then (3) dispose _networkStream — which OWNS the socket, so the FIN is deterministic.
        // Each step is independently guarded so one failure never skips the socket close.
        try {
            ShutdownSslBestEffort();
        }
        finally {
            try {
                _sslStream?.Dispose();
            }
            catch (Exception ex) {
                _logger.LogDebug(ex, "ServiceConnection.Close: SslStream dispose threw (ignored)");
            }
            _networkStream.Dispose();
        }
    }

    /// <summary>
    /// ScribeHold fork (#2197, P0-C): best-effort TLS <c>close_notify</c> before we tear the socket down,
    /// so a well-behaved peer sees a graceful application-layer close rather than only a bare FIN. Bounded
    /// to ~2s so a wedged/silent peer can never hang the teardown, and fully exception-safe — a failed or
    /// timed-out shutdown must never prevent the socket close that follows.
    /// </summary>
    private void ShutdownSslBestEffort() {
        SslStream? ssl = _sslStream;
        if (ssl == null) {
            return;
        }
        try {
            using CancellationTokenSource shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            ssl.ShutdownAsync().WaitAsync(shutdownCts.Token).GetAwaiter().GetResult();
        }
        catch (Exception ex) {
            // A wedged/closed peer, a timeout, or an already-disposed stream — all expected here; the
            // socket close in Close() is what actually releases the device.
            _logger.LogDebug(ex, "ServiceConnection.Close: SSL close_notify shutdown did not complete cleanly (ignored)");
        }
    }

    public void Dispose() {
        Close();
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
                // ScribeHold fork (#2068): the device sent a 0-byte read (FIN). Log WHERE in the
                // expected payload it died so a wedge self-explains: a FIN at offset 0 of a 4-byte
                // length-prefix read is the "empty-reply-FIN at version-exchange" signature, while a
                // FIN partway through a payload read is a truncated/partial reply.
                _logger.LogError(
                    "Read zero bytes so the connection has been broken (FIN at offset {Offset}/{Expected} bytes)",
                    totalBytesRead, length);
                // ScribeHold fork (#2077): version-exchange-window-bounded plaintext dump + close
                // classification (see ReceiveAsync for the full rationale).
                LogVersionExchangeFin(buffer, totalBytesRead, length);
                break;
            }
            totalBytesRead += bytesRead;
        }

        // ScribeHold fork (#2068): wire-level read trace, gated to Debug (Netimobiledevice category
        // is pinned to Warning unless EnableDiagnosticLogging raises it), so it is free when off.
        if (_logger.IsEnabled(LogLevel.Debug)) {
            _logger.LogDebug("ServiceConnection.Receive read {Read}/{Expected} bytes", totalBytesRead, length);
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
                            // ScribeHold fork (#2068): record WHERE the FIN landed — offset 0 of a 4-byte
                            // length-prefix read is the empty-reply-FIN-at-version-exchange signature.
                            _logger.LogError(
                                "Read zero bytes so the connection has been broken (FIN at offset {Offset}/{Expected} bytes)",
                                totalBytesRead, length);
                            // ScribeHold fork (#2077): at the version-exchange window only, dump the
                            // decrypted partial bytes (if any), confirm whether the host had sent
                            // anything first, and classify the close as graceful (close_notify / clean
                            // FIN) vs a hard RST — the decisive USB-vs-WiFi signal. Bounded to the
                            // version-exchange window so transfer-phase user content is never dumped.
                            LogVersionExchangeFin(buffer, totalBytesRead, length);
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

        // ScribeHold fork (#2068): wire-level read trace (Debug-gated, free when off).
        if (_logger.IsEnabled(LogLevel.Debug)) {
            _logger.LogDebug("ServiceConnection.ReceiveAsync read {Read}/{Expected} bytes", totalBytesRead, length);
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
        // ScribeHold fork (#2077): track total host-sent payload bytes so the version-exchange FIN
        // dump can prove whether the host wrote anything before the device FIN'd (it should not —
        // DeviceLink has the device speak first).
        Interlocked.Add(ref _bytesSent, data.Length);
    }

    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken) {
        await Stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        // ScribeHold fork (#2077): see Send — count host-sent bytes for the FIN dump.
        Interlocked.Add(ref _bytesSent, data.Length);
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
        return ReceivePlist();
    }

    public async Task<PropertyNode?> SendReceivePlistAsync(PropertyNode data, CancellationToken cancellationToken) {
        await SendPlistAsync(data, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await ReceivePlistAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Set a value in milliseconds, that determines how long the service connection will attempt to read/write for before timing out
    /// </summary>
    /// <param name="timeout">A value in milliseconds that detemines how long the service connection will wait before timing out</param>
    public void SetTimeout(int timeout = Timeout.Infinite) {
        // Update the internal timeout
        _timeout = timeout;

        // Update the currently active stream to use these timeouts.
        Stream.ReadTimeout = timeout;
        Stream.WriteTimeout = timeout;
    }

    public bool StartSsl(X509Certificate2 certificate) {
        if (_networkStream == null) {
            throw new InvalidOperationException("Network stream is null");
        }
        _networkStream.Flush();

        // ScribeHold fork (#1999): the SSL trust handshake must NOT carry the finite data-read
        // timeout (default 10_000 ms from the re-fork's ServiceConnection ctor). The device shows
        // a trust/passcode dialog during AuthenticateAsClient that legitimately takes longer than
        // 10 s; a finite stream timeout makes the host abort the relay socket (SocketException
        // 10053) and the handshake fails. Run the handshake with Timeout.Infinite (matching the
        // working marketing behavior), then restore _timeout so the subsequent #1857 bulk-read
        // budget — set explicitly via SetTimeout by DeviceLinkService — is preserved.
        _sslStream = new SslStream(_networkStream, true, UserCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption) {
            ReadTimeout = Timeout.Infinite,
            WriteTimeout = Timeout.Infinite
        };
        // ScribeHold fork (#2182): the synchronous AuthenticateAsClient honors the stream's
        // ReadTimeout, which is Infinite here (#1999), so a lost close_notify would hang forever.
        // Run it on a worker and bound the WAIT with the policy's SSL-handshake watchdog (~60s); on
        // a trip, tear down the handshake stream to unblock the worker and surface a bounded,
        // classifiable transport-drop signal that FEEDS reconnect-and-resume. The watchdog bounds only
        // the SSL wait — it does not clip the passcode/trust dialog window (#1999 intent preserved).
        SslStream handshakeStream = _sslStream;
        Task handshakeTask = Task.Run(() =>
            handshakeStream.AuthenticateAsClient(string.Empty, [certificate], SslProtocols.None, false));
        try {
            if (!handshakeTask.Wait(_timeoutPolicy.SslHandshakeWatchdog)) {
                // Watchdog tripped. Dispose the stream so the blocked AuthenticateAsClient unwinds,
                // then surface the bounded signal. The task is observed below to avoid an unobserved
                // exception when it finally faults on the torn-down stream.
                RestoreStreamTimeoutAfterHandshake();
                handshakeStream.Dispose();
                // The SslStream was constructed with leaveInnerStreamOpen:true, so disposing it does
                // NOT close _networkStream (which owns the socket). Null the disposed wrapper so a
                // later Dispose()/Close() on the discarded shell routes through _networkStream and
                // actually tears the socket down, rather than no-op'ing on the disposed SslStream and
                // leaking the socket (#2182).
                _sslStream = null;
                ObserveFaultedHandshake(handshakeTask);
                throw ThrowHandshakeWatchdogTimeout();
            }
            // Surface the handshake result/exception synchronously (unwrap AggregateException).
            handshakeTask.GetAwaiter().GetResult();
        }
        catch (TimeoutException) {
            throw;
        }
        catch (Exception ex) {
            _logger.LogError(ex, "SSL authentication failed");
            RestoreStreamTimeoutAfterHandshake();
            return false;
        }
        RestoreStreamTimeoutAfterHandshake();

        LogSslHandshakeResult();
        return true;
    }

    /// <summary>
    /// ScribeHold fork (#2182): build the bounded transport-drop signal raised when the SSL-handshake
    /// watchdog trips (a lost close_notify / stalled handshake). A <see cref="TimeoutException"/> with
    /// a distinct message so the coordinator classifies it as a recoverable transport drop
    /// (reconnect-and-resume) rather than a terminal failure. Returns the exception so callers can
    /// <c>throw</c> it and keep control-flow obvious.
    /// </summary>
    private TimeoutException ThrowHandshakeWatchdogTimeout() {
        _logger.LogError(
            "SSL handshake exceeded the {WatchdogSec}s watchdog bound (#2182) — treating as a recoverable transport drop",
            _timeoutPolicy.SslHandshakeWatchdogSec);
        return new TimeoutException(
            $"SSL handshake exceeded the {_timeoutPolicy.SslHandshakeWatchdogSec}s watchdog bound (#2182)");
    }

    /// <summary>
    /// ScribeHold fork (#2182): observe (and swallow) the fault of a handshake task that we abandoned
    /// after the watchdog tore down its stream. Best-effort and non-throwing — the abandoned task
    /// completing with an ObjectDisposedException/IOException on the disposed stream is expected and
    /// must not surface as an unobserved-task exception.
    /// </summary>
    private static void ObserveFaultedHandshake(Task handshakeTask) {
        _ = handshakeTask.ContinueWith(
            static t => { _ = t.Exception; },
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    public async Task<bool> StartSslAsync(X509Certificate2 certificate) {
        if (_networkStream == null) {
            throw new InvalidOperationException("Network stream is null");
        }
        await _networkStream.FlushAsync().ConfigureAwait(false);

        // ScribeHold fork (#1999): see StartSsl — handshake runs with Timeout.Infinite so the
        // trust/passcode dialog (which can exceed the 10 s data-read default) cannot abort the
        // socket, then _timeout is restored for the subsequent #1857-protected data reads.
        _sslStream = new SslStream(_networkStream, true, UserCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption) {
            ReadTimeout = Timeout.Infinite,
            WriteTimeout = Timeout.Infinite
        };
        // ScribeHold fork (#2182): bound the handshake with the policy's SSL-handshake watchdog
        // (~60s) so a lost close_notify during AuthenticateAsClient cannot hang forever at
        // Timeout.Infinite. The watchdog is generous enough not to clip a legitimate trust dialog
        // (#1999 intent preserved) yet bounded so a wedged handshake FEEDS reconnect-and-resume.
        using CancellationTokenSource watchdog = new CancellationTokenSource(_timeoutPolicy.SslHandshakeWatchdog);
        try {
            // TLS v1.2 is supported since iOS 5 so we should specify this as a minimum
            await _sslStream.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions {
                    TargetHost = string.Empty,
                    ClientCertificates = [certificate],
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                },
                watchdog.Token).ConfigureAwait(false);
        }
        catch (AuthenticationException ex) {
            _logger.LogError(ex, "SSL authentication failed");
            return false;
        }
        catch (OperationCanceledException) when (watchdog.IsCancellationRequested) {
            // ScribeHold fork (#2182): the ~60s SSL-handshake watchdog tripped — the handshake stalled
            // (e.g. a lost close_notify). Surface a bounded, classifiable transport-drop signal so the
            // coordinator can reconnect-and-resume rather than hang forever. Dispose+null the aborted
            // SslStream (leaveInnerStreamOpen:true, so it does not close the socket-owning
            // _networkStream) so a later Dispose() on the discarded shell tears the socket down via
            // _networkStream instead of no-op'ing on the aborted SslStream and leaking the socket.
            _sslStream?.Dispose();
            _sslStream = null;
            throw ThrowHandshakeWatchdogTimeout();
        }
        finally {
            RestoreStreamTimeoutAfterHandshake();
        }

        LogSslHandshakeResult();
        return true;
    }

    /// <summary>
    /// ScribeHold fork (#2068): on a successful handshake, log the negotiated TLS version and cipher
    /// suite (Debug-gated, free when the Netimobiledevice category is at its default Warning level).
    /// This distinguishes "SSL ok" from "SSL handshake threw" when diagnosing a version-exchange FIN.
    /// </summary>
    private void LogSslHandshakeResult() {
        if (_sslStream == null || !_logger.IsEnabled(LogLevel.Debug)) {
            return;
        }
        _logger.LogDebug(
            "SSL handshake established: protocol={Protocol} cipher={Cipher}",
            _sslStream.SslProtocol, _sslStream.NegotiatedCipherSuite);
    }

    /// <summary>
    /// Restore the configured data-read timeout (<see cref="_timeout"/>) onto the active SSL stream
    /// once the trust handshake has completed. The handshake itself runs with
    /// <see cref="Timeout.Infinite"/> so the device's trust/passcode dialog cannot abort the socket
    /// (#1999), but bulk data reads must keep the finite budget (#1857) that DeviceLinkService and
    /// the other services rely on via <see cref="SetTimeout"/>.
    /// </summary>
    private void RestoreStreamTimeoutAfterHandshake() {
        if (_sslStream == null) {
            return;
        }
        _sslStream.ReadTimeout = _timeout;
        _sslStream.WriteTimeout = _timeout;
    }

    /// <summary>
    /// ScribeHold fork (#2077): arm the version-exchange plaintext dump. Called by
    /// <see cref="Netimobiledevice.DeviceLink.DeviceLinkService"/> immediately before the first
    /// DeviceLink read on the mb2 service channel (where the empty-reply-FIN wedge bites). While the
    /// window is open, a 0-byte / short read MAY hex-dump the decrypted bytes it returned. The window
    /// MUST be closed (via <see cref="EndVersionExchangeWindow"/>, in a finally) the moment version
    /// exchange ends — the same SSL stream then carries the backup transfer (user message content),
    /// which must NEVER be dumped.
    /// </summary>
    public void BeginVersionExchangeWindow() {
        _versionExchangeWindow = true;
    }

    /// <summary>
    /// ScribeHold fork (#2077): disarm the version-exchange plaintext dump. After this returns, a
    /// 0-byte read on the transfer phase only emits the #2068 byte-count trace (no payload), so user
    /// content on the same SSL stream is structurally unable to be dumped.
    /// </summary>
    public void EndVersionExchangeWindow() {
        _versionExchangeWindow = false;
    }

    /// <summary>
    /// ScribeHold fork (#2077): cumulative count of payload bytes the host has written on this
    /// connection. Exposed so callers (and the diagnostic trace) can confirm the host did not send a
    /// stray byte before the device-speaks-first DeviceLink read.
    /// </summary>
    public long HostBytesSent => Interlocked.Read(ref _bytesSent);

    /// <summary>
    /// ScribeHold fork (#2077): the decisive version-exchange-FIN dump. Runs ONLY inside the
    /// version-exchange window (armed by <see cref="BeginVersionExchangeWindow"/>) and only when
    /// Debug logging is enabled (the Netimobiledevice category is pinned to Warning unless
    /// EnableDiagnosticLogging raises it), so it is free and silent when the diagnostic switch is off.
    /// Surfaces, at the exact FIN: (1) whether the host had written anything before the first read
    /// (AC1), (2) the decrypted partial bytes the SSL read returned, length + hex (AC2), and (3)
    /// whether the device closed gracefully (close_notify / clean FIN) or hard-RST the socket (AC3).
    /// </summary>
    /// <param name="buffer">The receive buffer; the first <paramref name="bytesRead"/> bytes are the decrypted partial.</param>
    /// <param name="bytesRead">How many bytes were decrypted before the 0-byte read (0 at the canonical 0/4 FIN).</param>
    /// <param name="expected">The number of bytes the read was waiting for (4 at the length-prefix FIN).</param>
    private void LogVersionExchangeFin(byte[] buffer, int bytesRead, int expected) {
        if (!_versionExchangeWindow || !_logger.IsEnabled(LogLevel.Debug)) {
            return;
        }

        string partialHex = FormatHexPreview(buffer, bytesRead);
        string closeKind = ClassifyConnectionClose();
        _logger.LogDebug(
            "VersionExchange FIN dump: hostBytesSentBeforeRead={HostBytesSent} decryptedPartial={Read}/{Expected} bytes hex=[{Hex}] close={Close}",
            HostBytesSent, bytesRead, expected, partialHex, closeKind);
    }

    /// <summary>
    /// ScribeHold fork (#2077): classify a 0-byte SSL read on the mb2 service channel as a graceful
    /// close (TLS <c>close_notify</c> alert or a clean TCP FIN — the device deliberately tore the
    /// channel down at the application layer) vs a hard <c>RST</c> (transport-level abort). This is THE
    /// signal that separates "Apple's mb2 logic refused something" from "the socket was killed under
    /// us". Probes the underlying <see cref="Socket"/>: a connected-but-readable-with-0-available
    /// socket after an SslStream EOF is a graceful close; <see cref="Socket.Poll(int, SelectMode)"/>
    /// surfacing an error condition, or a zero-byte send raising a connection-reset
    /// <see cref="SocketException"/>, is an RST. Best-effort and exception-safe — diagnostics must
    /// never throw into the read path.
    /// </summary>
    private string ClassifyConnectionClose() {
        try {
            Socket socket = _networkStream.Socket;

            // SelectError surfaces an out-of-band/error condition (a received RST sets this).
            bool errored = socket.Poll(0, SelectMode.SelectError);
            if (errored) {
                return "rst (socket error condition)";
            }

            // A zero-byte send forces the stack to surface a pending RST as ConnectionReset without
            // moving any application data. On a graceful FIN this succeeds (the local side may still
            // send) or reports a clean shutdown.
            try {
                socket.Send(Array.Empty<byte>(), 0, SocketFlags.None);
            }
            catch (SocketException sex) when (sex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.NetworkReset) {
                return $"rst ({sex.SocketErrorCode})";
            }

            // Readable with nothing available, after an SslStream EOF, is the signature of a graceful
            // peer close (close_notify or a clean FIN). We cannot tell close_notify from a bare FIN
            // through the managed SslStream API, so report the graceful class explicitly.
            bool readable = socket.Poll(0, SelectMode.SelectRead);
            if (readable && socket.Available == 0) {
                return "graceful (close_notify / clean FIN — no RST)";
            }

            return socket.Connected ? "graceful (peer EOF, socket still connected)" : "graceful (peer EOF, socket closed)";
        }
        catch (ObjectDisposedException) {
            return "unknown (socket disposed)";
        }
        catch (SocketException sex) {
            return $"unknown ({sex.SocketErrorCode})";
        }
    }

    /// <summary>
    /// ScribeHold fork (#2077): render up to <paramref name="count"/> bytes of a buffer as a
    /// space-separated lowercase hex preview, capped so a stray large read can never balloon the log.
    /// "&lt;none&gt;" for an empty/0-byte read (the canonical version-exchange FIN). Pure + static so
    /// the fork regression test exercises identical formatting.
    /// </summary>
    internal static string FormatHexPreview(byte[] buffer, int count) {
        if (buffer == null || count <= 0) {
            return "<none>";
        }
        const int maxBytes = 64;
        int take = Math.Min(count, Math.Min(buffer.Length, maxBytes));
        string hex = BitConverter.ToString(buffer, 0, take).Replace('-', ' ').ToLowerInvariant();
        return count > take ? $"{hex} … (+{count - take} more)" : hex;
    }
}
