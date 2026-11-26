namespace Netimobiledevice.Backup;

public class DeviceLinkException(string message) : NetimobiledeviceException(message)
{
    public ulong? DeviceErrorCode { get; init; }
}
