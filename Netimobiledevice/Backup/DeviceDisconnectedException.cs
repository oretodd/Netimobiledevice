namespace Netimobiledevice.Backup;

/// <summary>
/// Exception thrown when the device is disconnected.
/// </summary>
public class DeviceDisconnectedException : NetimobiledeviceException
{
    public DeviceDisconnectedException() : base("Device disconnected") { }
}
