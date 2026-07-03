using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for the DownloadFiles composite obligation (#2198, P1-6).
///
/// Background: DownloadFiles owes the device, in ORDER: per-file framing completion, the
/// FILE_TRANSFER_TERMINATOR (empty dword), then exactly one terminating DLMessageStatusResponse. The
/// #2181 <see cref="DeviceLinkResponseGuarantee"/> guaranteed only the STATUS: a cancel mid-file-loop
/// made its dispose fallback send a status PLIST while the device was still in file-data framing —
/// protocol desync on the very session the host then resumes. The
/// <see cref="DownloadFilesObligation"/> wraps framing + terminator + status as one exactly-once
/// composite, discharged explicitly on success or — bounded, in order — by its dispose fallback.
/// </summary>
[TestClass]
public class DownloadFilesObligationTests
{
    private readonly List<string> _wire = [];
    private int _statusSends;

    private DownloadFilesObligation CreateObligation()
    {
        DeviceLinkRawSender raw = (data, ct) => {
            _wire.Add($"raw:{Convert.ToHexString(data.Span)}");
            return Task.CompletedTask;
        };
        DeviceLinkPrefixedSender prefixed = (data, length, ct) => {
            _wire.Add($"prefixed:code={data[0]}");
            return Task.CompletedTask;
        };
        DeviceLinkStatusSender statusSender = (errorCode, errorMessage, payload, ct) => {
            _statusSends++;
            _wire.Add($"status:code={errorCode}");
            return Task.CompletedTask;
        };
        return new DownloadFilesObligation(raw, prefixed, new DeviceLinkResponseGuarantee(statusSender), NullLogger.Instance);
    }

    private const string TerminatorWire = "raw:00000000"; // FILE_TRANSFER_TERMINATOR: empty dword
    private const byte LocalErrorCode = 0x06;             // ResultCode.LocalError

    [TestMethod]
    [Description("#2198 P1-6 (failing-shape repro): a cancel MID-FILE makes the dispose fallback emit per-file error framing FIRST, then the terminator, then exactly ONE status — never a bare status plist into file-data framing.")]
    public async Task CancelMidFile_FallbackEmits_FramingError_Terminator_Status_InOrder()
    {
        DownloadFilesObligation obligation = CreateObligation();
        obligation.BeginFileFraming("Snapshot/Manifest.db");
        // Handler is cancelled here: no EndFileFraming, no terminator, no explicit status.

        await obligation.DisposeAsync();

        Assert.AreEqual(3, _wire.Count, $"Fallback must emit exactly framing-error, terminator, status — got: {string.Join(", ", _wire)}");
        Assert.AreEqual($"prefixed:code={LocalErrorCode}", _wire[0],
            "FIRST the interrupted file's framing must be completed with a per-file error code so the device exits file-data mode.");
        Assert.AreEqual(TerminatorWire, _wire[1],
            "THEN the FILE_TRANSFER_TERMINATOR (empty dword) ends the transfer framing.");
        Assert.AreEqual("status:code=0", _wire[2],
            "ONLY THEN the terminating status plist goes out — the device is back in plist framing.");
        Assert.AreEqual(1, _statusSends, "Exactly one terminating status, ever.");
    }

    [TestMethod]
    [Description("#2198 P1-6: a cancel BETWEEN files (framing closed) falls back to terminator + status only — no spurious file-error framing.")]
    public async Task CancelBetweenFiles_FallbackEmits_Terminator_Status_Only()
    {
        DownloadFilesObligation obligation = CreateObligation();
        obligation.BeginFileFraming("a.file");
        obligation.EndFileFraming(); // per-file code was sent by the handler

        await obligation.DisposeAsync();

        Assert.AreEqual(2, _wire.Count, $"Got: {string.Join(", ", _wire)}");
        Assert.AreEqual(TerminatorWire, _wire[0]);
        Assert.AreEqual("status:code=0", _wire[1]);
        Assert.AreEqual(1, _statusSends);
    }

    [TestMethod]
    [Description("#2198 P1-6: the explicit success path discharges the whole obligation; dispose adds NOTHING (terminator and status are exactly-once).")]
    public async Task ExplicitSuccessPath_DisposeAddsNothing()
    {
        DownloadFilesObligation obligation = CreateObligation();
        obligation.BeginFileFraming("a.file");
        obligation.EndFileFraming();
        await obligation.SendTerminatorAsync(CancellationToken.None);
        await obligation.SendTerminatingStatusAsync(0, null, null, CancellationToken.None);

        await obligation.DisposeAsync();

        Assert.AreEqual(2, _wire.Count, $"Got: {string.Join(", ", _wire)}");
        Assert.AreEqual(TerminatorWire, _wire[0]);
        Assert.AreEqual("status:code=0", _wire[1]);
        Assert.AreEqual(1, _statusSends, "The dispose fallback must be a no-op once the obligation was discharged explicitly.");
    }

    [TestMethod]
    [Description("#2198 P1-6: the error path (missing files) still sends terminator before the multi-status, exactly once each.")]
    public async Task ErrorStatusPath_TerminatorPrecedesStatus()
    {
        DownloadFilesObligation obligation = CreateObligation();
        await obligation.SendTerminatorAsync(CancellationToken.None);
        await obligation.SendTerminatingStatusAsync(-13, "Multi status", new DictionaryNode(), CancellationToken.None);

        await obligation.DisposeAsync();

        Assert.AreEqual(2, _wire.Count);
        Assert.AreEqual(TerminatorWire, _wire[0]);
        Assert.AreEqual("status:code=-13", _wire[1]);
        Assert.AreEqual(1, _statusSends);
    }

    [TestMethod]
    [Description("#2198 P1-6: the terminator is latched exactly-once — a duplicate explicit send is a no-op.")]
    public async Task Terminator_IsExactlyOnce()
    {
        DownloadFilesObligation obligation = CreateObligation();
        await obligation.SendTerminatorAsync(CancellationToken.None);
        await obligation.SendTerminatorAsync(CancellationToken.None);

        Assert.AreEqual(1, _wire.Count(w => w == TerminatorWire));
        Assert.IsTrue(obligation.TerminatorSent);
        await obligation.DisposeAsync();
        Assert.AreEqual(1, _wire.Count(w => w == TerminatorWire), "Dispose must not re-send a latched terminator.");
    }

    [TestMethod]
    [Description("#2198 P1-6: a failing fallback send never throws out of DisposeAsync (must not mask the handler's own in-flight exception) — and the status guarantee still gets its bounded chance.")]
    public async Task FallbackSendFailure_NeverThrows_StatusStillAttempted()
    {
        DeviceLinkRawSender raw = (data, ct) => throw new IOException("socket gone");
        DeviceLinkPrefixedSender prefixed = (data, length, ct) => throw new IOException("socket gone");
        DeviceLinkStatusSender statusSender = (errorCode, errorMessage, payload, ct) => {
            _statusSends++;
            return Task.CompletedTask;
        };
        DownloadFilesObligation obligation = new(raw, prefixed, new DeviceLinkResponseGuarantee(statusSender), NullLogger.Instance);
        obligation.BeginFileFraming("a.file");

        await obligation.DisposeAsync(); // must not throw

        Assert.AreEqual(1, _statusSends,
            "Even when framing/terminator sends fail (dead socket), the status guarantee still runs its own bounded fallback.");
    }
}
