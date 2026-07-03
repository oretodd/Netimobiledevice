using Microsoft.Extensions.Logging;
using Netimobiledevice.Backup;
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.DeviceLink;

/// <summary>
/// ScribeHold fork (#2198, P1-6): the delegate that writes a raw byte payload onto the mb2 service
/// channel (bound to <c>ServiceConnection.SendAsync</c>). Narrow function type so the obligation is
/// decoupled from the connection and unit-testable against a capturing fake (no live socket).
/// </summary>
public delegate Task DeviceLinkRawSender(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);

/// <summary>
/// ScribeHold fork (#2198, P1-6): the delegate that writes a u32-length-prefixed payload onto the mb2
/// service channel (bound to <c>DeviceLinkService.SendPrefixed</c>).
/// </summary>
public delegate Task DeviceLinkPrefixedSender(byte[] data, int length, CancellationToken cancellationToken);

/// <summary>
/// ScribeHold fork (#2198, P1-6): the COMPOSITE exactly-once obligation a <c>DownloadFiles</c> handler
/// owes the device. The wire protocol requires, in ORDER: (a) each in-flight file's framing completed
/// with a per-file result/error code, (b) the FILE_TRANSFER_TERMINATOR (empty dword), and only THEN
/// (c) the single terminating <c>DLMessageStatusResponse</c>. The #2181
/// <see cref="DeviceLinkResponseGuarantee"/> guarantees exactly-one STATUS — but the terminator escaped
/// it: a cancellation mid-file-loop made the guarantee's dispose fallback send a status PLIST while the
/// device was still in file-data framing, desyncing the protocol on the very session the host then
/// resumes. This collaborator wraps terminator+status (plus the pending file's framing) as ONE
/// exactly-once composite obligation, discharged on the explicit success path or — bounded, in order —
/// by the dispose fallback.
///
/// The fallback is best-effort by design: if cancellation tore a chunk write mid-bytes the framing is
/// beyond repair (bytes we inject would be read as chunk content) and the sends simply fail/time out;
/// the ~5s bound (matching the #2189 status-fallback bound) guarantees teardown is never hung either way.
/// </summary>
public sealed class DownloadFilesObligation : IAsyncDisposable
{
    /// <summary>The mb2 file-transfer terminator: an empty dword (u32 0) ending the file-data framing.</summary>
    private const uint FILE_TRANSFER_TERMINATOR = 0x00;

    /// <summary>
    /// The hard upper bound on the WHOLE dispose-fallback sequence (file-framing error + terminator);
    /// the status fallback that follows carries its own ~5s bound inside
    /// <see cref="DeviceLinkResponseGuarantee.DisposeAsync"/>. Mirrors the #2189 rationale: the
    /// obligation must be attempted, but a wedged socket must never hang the teardown.
    /// </summary>
    private static readonly TimeSpan DisposeFallbackTimeout = TimeSpan.FromSeconds(5);

    private readonly DeviceLinkRawSender _sendRaw;
    private readonly DeviceLinkPrefixedSender _sendPrefixed;
    private readonly IDeviceLinkResponseGuarantee _statusGuarantee;
    private readonly ILogger _logger;

    // The device-side path of the file whose framing is currently OPEN (path sent, per-file result code
    // not yet sent); null when between files. Volatile: the dispose fallback may run on a different
    // continuation thread than the handler loop.
    private volatile string? _openFileFraming;
    // Latch: 0 = terminator not yet sent, 1 = sent. The terminator is sent exactly once.
    private int _terminatorSent;

    public DownloadFilesObligation(
        DeviceLinkRawSender sendRaw,
        DeviceLinkPrefixedSender sendPrefixed,
        IDeviceLinkResponseGuarantee statusGuarantee,
        ILogger logger)
    {
        _sendRaw = sendRaw ?? throw new ArgumentNullException(nameof(sendRaw));
        _sendPrefixed = sendPrefixed ?? throw new ArgumentNullException(nameof(sendPrefixed));
        _statusGuarantee = statusGuarantee ?? throw new ArgumentNullException(nameof(statusGuarantee));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>True while a file's framing is open (path sent, per-file result code not yet sent).</summary>
    public bool IsFileFramingOpen => _openFileFraming != null;

    /// <summary>True once the FILE_TRANSFER_TERMINATOR has been sent (latched; sent exactly once).</summary>
    public bool TerminatorSent => Volatile.Read(ref _terminatorSent) == 1;

    /// <summary>
    /// Mark the given file's framing OPEN. Called immediately before the handler sends the file's path —
    /// from that moment the device expects file-data framing (chunks + a per-file result code), and a
    /// terminating status plist would desync it.
    /// </summary>
    public void BeginFileFraming(string devicePath)
    {
        _openFileFraming = devicePath;
    }

    /// <summary>
    /// Mark the current file's framing CLOSED. Called after the handler sends the per-file result code
    /// (<see cref="ResultCode.Success"/>) or the per-file error report.
    /// </summary>
    public void EndFileFraming()
    {
        _openFileFraming = null;
    }

    /// <summary>
    /// Send the FILE_TRANSFER_TERMINATOR (empty dword) exactly once. The explicit success path calls
    /// this after the file loop; the dispose fallback calls it (bounded) if the handler never did.
    /// A failed send un-latches so the fallback may retry the still-owed obligation.
    /// </summary>
    public async Task SendTerminatorAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _terminatorSent, 1) == 1) {
            return;
        }
        try {
            await _sendRaw(BitConverter.GetBytes(FILE_TRANSFER_TERMINATOR), cancellationToken).ConfigureAwait(false);
        }
        catch {
            Volatile.Write(ref _terminatorSent, 0);
            throw;
        }
    }

    /// <summary>
    /// Send the terminating <c>DLMessageStatusResponse</c> through the exactly-once status guarantee.
    /// Callers must send the terminator FIRST (the explicit path does; the fallback enforces the order).
    /// </summary>
    public Task SendTerminatingStatusAsync(int errorCode, string? errorMessage, Plist.PropertyNode? payload, CancellationToken cancellationToken)
    {
        return _statusGuarantee.SendTerminatingStatusAsync(errorCode, errorMessage, payload, cancellationToken);
    }

    /// <summary>
    /// The composite dispose fallback. If the handler was cancelled (or threw) before discharging the
    /// obligation, this completes it IN ORDER — (a) close any open file framing with a per-file error
    /// code so the device exits file-data mode, (b) send the terminator, then (c) let the status
    /// guarantee discharge the exactly-one terminating status — all bounded so a wedged socket can
    /// never hang the teardown, and never throwing over the handler's own in-flight exception.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        using CancellationTokenSource timeoutCts = new CancellationTokenSource(DisposeFallbackTimeout);
        try {
            string? openFile = _openFileFraming;
            if (openFile != null) {
                _logger.LogWarning(
                    "DownloadFiles obligation fallback: completing interrupted file framing for {File} with a per-file error before terminator+status (#2198 P1-6)",
                    openFile);
                byte[] errBytes = Encoding.UTF8.GetBytes("Transfer interrupted by host");
                byte[] framingError = new byte[1 + errBytes.Length];
                framingError[0] = (byte) ResultCode.LocalError;
                errBytes.CopyTo(framingError, 1);
                await _sendPrefixed(framingError, framingError.Length, timeoutCts.Token).ConfigureAwait(false);
                _openFileFraming = null;
            }
            if (!TerminatorSent) {
                _logger.LogWarning(
                    "DownloadFiles obligation fallback: sending FILE_TRANSFER_TERMINATOR before the terminating status (#2198 P1-6)");
                await SendTerminatorAsync(timeoutCts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) {
            // Best-effort: the socket may be gone (the same drop that cancelled the handler) or the
            // bound elapsed. Never throw over the handler's own propagating exception.
            _logger.LogDebug(ex, "DownloadFiles obligation fallback send failed (ignored) (#2198 P1-6)");
        }
        finally {
            // Exactly-one terminating status — the guarantee's own dispose fallback (bounded ~5s) sends
            // it if the handler never did. Runs AFTER framing+terminator so the order is preserved.
            await _statusGuarantee.DisposeAsync().ConfigureAwait(false);
        }
    }
}
