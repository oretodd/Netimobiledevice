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
