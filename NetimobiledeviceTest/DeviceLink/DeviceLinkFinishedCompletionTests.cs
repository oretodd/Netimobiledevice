using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork regression tests for the "backup finishes but the device holds the connection open" hang
/// (#2081).
///
/// Background: <c>DeviceLinkService.DlLoop</c> historically detected completion only via the device
/// sending the terminating <c>DLMessageProcessMessage</c> (or the connection closing / a benign
/// protocol error). When a device reached the terminal <c>SnapshotState=Finished</c> state but held
/// the TCP connection OPEN — no FIN, no terminating message (observed live on WiFi) — the loop blocked
/// on the long <c>SERVICE_READ_TIMEOUT_MS</c> read until it timed out and then FAILED, leaving the
/// backup hung at 100% with no extraction.
///
/// The fix latches the Finished observation (<c>OnStatusReceived</c>) and, once latched, bounds the
/// next read to a short timeout. If that short read times out or returns an empty message, the loop
/// completes gracefully as success — because Finished is the terminal state. These tests pin the pure
/// decision (<see cref="DeviceLinkService.ShouldCompleteAfterFinished"/>) that gates that early-exit,
/// and confirm the terminal-state enum value the latch keys off has not drifted.
/// </summary>
[TestClass]
public class DeviceLinkFinishedCompletionTests
{
    /// <summary>
    /// The desync this fix targets: after Finished, the short final read timed out (the device sent
    /// nothing more on the held-open connection). The loop must complete gracefully as success.
    /// </summary>
    [TestMethod]
    public void ShouldCompleteAfterFinished_TimedOut_CompletesGracefully()
    {
        Assert.IsTrue(
            DeviceLinkService.ShouldCompleteAfterFinished(finishedTimedOut: true, messageCount: 0),
            "A short-read timeout after Finished means the device is done but holding the connection open — complete as success.");
    }

    /// <summary>
    /// An empty message (0-byte read / FIN with no plist) after Finished is the same conclusion as a
    /// timeout: nothing more is coming, the terminal state was reached, complete gracefully.
    /// </summary>
    [TestMethod]
    public void ShouldCompleteAfterFinished_EmptyMessageNoTimeout_CompletesGracefully()
    {
        Assert.IsTrue(
            DeviceLinkService.ShouldCompleteAfterFinished(finishedTimedOut: false, messageCount: 0),
            "An empty reply after Finished means no terminating message will arrive — complete as success.");
    }

    /// <summary>
    /// A real terminating message arrived within the short bound (e.g. the device finally sent its
    /// DLMessageProcessMessage). The loop must NOT short-circuit here — it must fall through to the
    /// normal switch so the message is handled (and any error ErrorCode still throws).
    /// </summary>
    [TestMethod]
    public void ShouldCompleteAfterFinished_RealMessageArrived_DoesNotShortCircuit()
    {
        Assert.IsFalse(
            DeviceLinkService.ShouldCompleteAfterFinished(finishedTimedOut: false, messageCount: 1),
            "A non-empty message within the bound is a real terminating message and must be handled by the normal switch, not short-circuited.");
        Assert.IsFalse(
            DeviceLinkService.ShouldCompleteAfterFinished(finishedTimedOut: false, messageCount: 3),
            "A multi-element message within the bound must likewise be handled normally.");
    }

    /// <summary>
    /// The fix latches off the terminal <see cref="SnapshotState.Finished"/> enum value. If that value
    /// or its position drifts, <c>OnStatusReceived</c> would stop latching and the hang would silently
    /// return — so pin it as the explicit terminal state.
    /// </summary>
    [TestMethod]
    public void Finished_IsTheTerminalSnapshotState()
    {
        // Finished is the highest-ordinal real Status.plist state (after Uploading/Moving/Removing).
        // Compute the max ordinal from the live enum values so the check is not a compile-time constant
        // and would fail if a new higher-ordinal state were added ahead of Finished.
        int maxOrdinal = Enum.GetValues<SnapshotState>().Max(s => (int) s);
        Assert.AreEqual((int) SnapshotState.Finished, maxOrdinal,
            "Finished must remain the terminal (highest-ordinal) state the completion latch keys off.");
        Assert.AreEqual("Finished", SnapshotState.Finished.ToString(),
            "The latch compares against SnapshotState.Finished by name in OnStatusReceived; the name must not drift.");
    }
}
