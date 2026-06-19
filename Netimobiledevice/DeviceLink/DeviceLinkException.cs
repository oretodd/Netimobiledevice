namespace Netimobiledevice.DeviceLink;

public class DeviceLinkException(string message) : NetimobiledeviceException(message)
{
}

/// <summary>
/// Raised when a DeviceLink read returns an EMPTY reply — the device accepted the connection (and,
/// for mobilebackup2, completed the SSL handshake) but then sent nothing and closed its end with a
/// TCP FIN, so <c>ReceiveMessage</c> read 0 bytes (ScribeHold #1932 guard).
/// <para>
/// This is a strict subtype of <see cref="DeviceLinkException"/>, so every existing
/// <c>catch (DeviceLinkException)</c> still catches it unchanged — it merely lets callers that care
/// about the empty-reply case specifically (e.g. classifying the WiFi stale-escrow wedge, ScribeHold
/// #1945) distinguish it from a malformed/version-mismatch reply WITHOUT fragile message-string matching.
/// </para>
/// </summary>
public sealed class EmptyDeviceLinkReplyException(string message) : DeviceLinkException(message)
{
}

/// <summary>
/// Raised when the mobilebackup2 daemon reports a non-zero <c>ErrorCode</c> in a
/// <c>DLMessageProcessMessage</c>. Carries the raw daemon errno so callers can react to specific codes
/// (e.g. ScribeHold #1954: errno <see cref="DeviceLockedErrorCode"/> = the device auto-locked mid-backup,
/// which is recoverable by re-prompting the passcode and re-running the backup, rather than a fatal error).
/// <para>
/// A strict subtype of <see cref="DeviceLinkException"/>, so every existing
/// <c>catch (DeviceLinkException)</c> still catches it unchanged — it merely lets callers that care about
/// a specific daemon errno distinguish it WITHOUT fragile message-string parsing of the serialized plist.
/// </para>
/// </summary>
public sealed class DeviceLinkServiceException : DeviceLinkException
{
    /// <summary>
    /// mobilebackup2 daemon errno for a device that is passcode-locked. iOS auto-lock (no "Never" option on
    /// many devices) fires this mid-backup once the screen locks, ending any backup longer than the auto-lock
    /// timeout unless the host re-prompts + resumes (ScribeHold #1954 P0).
    /// </summary>
    public const int DeviceLockedErrorCode = 208;

    /// <summary>The raw daemon errno reported in the <c>DLMessageProcessMessage</c> dictionary.</summary>
    public int ErrorCode { get; }

    public DeviceLinkServiceException(int errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>True when the daemon reported the device-locked errno (<see cref="DeviceLockedErrorCode"/>).</summary>
    public bool IsDeviceLocked => ErrorCode == DeviceLockedErrorCode;
}
