using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;

namespace NetimobiledeviceTest.Backup;

/// <summary>
/// Fork tests for the bounded passcode wait (#2198, P1-4).
///
/// Background: the passcode wait was <c>do { Task.Delay(3000) } while (_passcodeRequired)</c> — NO
/// deadline, and the flag was a plain (non-volatile) bool set from the NotificationProxy thread. A
/// user who walked away from the device prompt parked the backup forever with no signal. The wait now
/// enforces a configurable deadline (<c>PasscodeWaitMaxSec</c>, ~300s default) and surfaces a
/// dedicated <see cref="PasscodeWaitTimeoutException"/> the host maps to its EXISTING actionable
/// passcode terminal — never a generic fatal, and never the transient reconnect ladder.
/// </summary>
[TestClass]
public class PasscodeWaitTests
{
    private static readonly TimeSpan FastPoll = TimeSpan.FromMilliseconds(10);

    [TestMethod]
    [Timeout(10000)]
    [Description("#2198 P1-4 (failing-shape repro): a passcode prompt that stays unanswered past the deadline raises PasscodeWaitTimeoutException — provably NOT an unbounded wait.")]
    public async Task UnansweredPasscode_ExceedsDeadline_Throws()
    {
        TimeSpan deadline = TimeSpan.FromMilliseconds(80);

        PasscodeWaitTimeoutException ex = await Assert.ThrowsExactlyAsync<PasscodeWaitTimeoutException>(
            () => Mobilebackup2Service.WaitForPasscodeEntryAsync(
                passcodeRequired: () => true, FastPoll, deadline, NullLogger.Instance, CancellationToken.None),
            "An unanswered passcode prompt must surface the dedicated deadline exception, not wait forever.");

        Assert.AreEqual(deadline, ex.Deadline, "The exception carries the deadline that was exceeded.");
    }

    [TestMethod]
    [Description("#2198 P1-4: the deadline exception is a Mobilebackup2Exception (actionable terminal), NOT a TimeoutException — it must never ride the transient transport-drop reconnect ladder.")]
    public void PasscodeWaitTimeout_IsActionableTerminal_NotTransientTimeout()
    {
        PasscodeWaitTimeoutException ex = new(TimeSpan.FromSeconds(300));

        Assert.IsInstanceOfType<Mobilebackup2Exception>(ex);
        Assert.IsNotInstanceOfType<TimeoutException>(ex,
            "A user-action-needed terminal must not classify as a transient timeout — reconnect-and-resume would re-prompt in a loop.");
        Assert.IsTrue(ex.Message.Contains("passcode", StringComparison.OrdinalIgnoreCase),
            "The message names the user action so the host terminal is self-explanatory.");
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2198 P1-4: a passcode entered BEFORE the deadline lets the wait return normally.")]
    public async Task PasscodeEntered_BeforeDeadline_ReturnsNormally()
    {
        int polls = 0;
        // Prompt raised for the first three polls, then the user enters the passcode (flag clears).
        bool PasscodeRequired() => ++polls <= 3;

        await Mobilebackup2Service.WaitForPasscodeEntryAsync(
            PasscodeRequired, FastPoll, TimeSpan.FromSeconds(30), NullLogger.Instance, CancellationToken.None);

        Assert.IsTrue(polls >= 4, "The wait must poll until the prompt clears, then return.");
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2198 P1-4: when the passcode prompt never appears, the wait is a single grace poll and returns (the legacy 3s-probe behavior).")]
    public async Task NoPasscodePrompt_SingleGracePoll_Returns()
    {
        await Mobilebackup2Service.WaitForPasscodeEntryAsync(
            passcodeRequired: () => false, FastPoll, TimeSpan.FromMilliseconds(50), NullLogger.Instance, CancellationToken.None);
    }

    [TestMethod]
    [Description("#2198 P1-4: the pure deadline decision — a non-positive deadline DISABLES the bound (legacy opt-out), a positive one expires at/after the deadline.")]
    public void IsPasscodeWaitExpired_PureBoundary()
    {
        Assert.IsFalse(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromHours(5), TimeSpan.Zero),
            "A zero deadline disables the bound (never expires).");
        Assert.IsFalse(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromHours(5), TimeSpan.FromSeconds(-1)),
            "A negative deadline likewise disables the bound.");
        Assert.IsFalse(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromSeconds(299), TimeSpan.FromSeconds(300)),
            "Under the deadline the wait continues.");
        Assert.IsTrue(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromSeconds(300), TimeSpan.FromSeconds(300)),
            "At the deadline the wait expires.");
    }

    [TestMethod]
    [Description("#2198 P1-4: the library default deadline is 300s (from DefaultPasscodeWaitMaxSec) and expires by the pure boundary at exactly that point.")]
    public void DefaultDeadline_Is300s_AndGovernsExpiry()
    {
        TimeSpan defaultDeadline = TimeSpan.FromSeconds(Mobilebackup2Service.DefaultPasscodeWaitMaxSec);
        Assert.IsFalse(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromMinutes(4.9), defaultDeadline));
        Assert.IsTrue(Mobilebackup2Service.IsPasscodeWaitExpired(TimeSpan.FromMinutes(5), defaultDeadline),
            "The default deadline is the ~300s design value from #2198 P1-4.");
    }

    [TestMethod]
    [Timeout(10000)]
    [Description("#2198 P1-4: a caller cancellation propagates as-is (never reclassified as the passcode deadline).")]
    public async Task CallerCancellation_Propagates()
    {
        using CancellationTokenSource cts = new();
        cts.CancelAfter(TimeSpan.FromMilliseconds(30));

        Exception ex = await Assert.ThrowsAsync<OperationCanceledException>(
            () => Mobilebackup2Service.WaitForPasscodeEntryAsync(
                passcodeRequired: () => true, FastPoll, TimeSpan.FromSeconds(30), NullLogger.Instance, cts.Token));
        Assert.IsNotInstanceOfType<PasscodeWaitTimeoutException>(ex);
    }
}
