using System;

namespace Netimobiledevice.Backup;

/// <summary>
/// ScribeHold fork (#2198, P1-4): raised when the device's backup-passcode prompt stays unanswered
/// longer than the configured deadline (<c>Mobilebackup2Service.PasscodeWaitMax</c>, host key
/// <c>PasscodeWaitMaxSec</c>, ~300s default). The prior wait —
/// <c>do { Task.Delay(3000) } while (_passcodeRequired)</c> — had NO deadline: a user who walked away
/// from the prompt parked the backup forever with no signal. The dedicated type lets the host map the
/// exhaustion to its EXISTING actionable passcode terminal ("enter your passcode on the device…")
/// instead of a generic fatal. Deliberately NOT a <see cref="TimeoutException"/>: this is a
/// user-action-needed terminal, and it must never ride the transient transport-drop ladder into
/// reconnect-and-resume (which could re-prompt in a loop).
/// </summary>
public sealed class PasscodeWaitTimeoutException : Mobilebackup2Exception
{
    public PasscodeWaitTimeoutException(TimeSpan deadline)
        : base($"Device passcode was not entered within the {deadline.TotalSeconds:0.###}s deadline — the backup cannot start until the passcode is entered on the device")
    {
        Deadline = deadline;
    }

    /// <summary>The passcode-wait deadline that was exceeded.</summary>
    public TimeSpan Deadline { get; }
}
