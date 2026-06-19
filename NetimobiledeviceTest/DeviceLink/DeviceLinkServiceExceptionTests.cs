using Netimobiledevice;
using Netimobiledevice.DeviceLink;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Contract for <see cref="DeviceLinkServiceException"/> — the typed surface for a non-zero mobilebackup2
/// daemon errno reported in a DLMessageProcessMessage (ScribeHold #1954). It must remain a strict subtype
/// of <see cref="DeviceLinkException"/> (so existing catch blocks are unaffected) while carrying the raw
/// errno so callers can react to errno 208 (device auto-locked mid-backup) without parsing the plist.
/// </summary>
[TestClass]
public class DeviceLinkServiceExceptionTests
{
    [TestMethod]
    public void CarriesErrorCode_AndMessage()
    {
        var ex = new DeviceLinkServiceException(208, "Device link error (ErrorCode 208): <plist/>");

        Assert.AreEqual(208, ex.ErrorCode);
        Assert.IsTrue(ex.Message.Contains("208"));
    }

    [TestMethod]
    public void IsDeviceLocked_True_OnErrorCode208()
    {
        var ex = new DeviceLinkServiceException(DeviceLinkServiceException.DeviceLockedErrorCode, "locked");

        Assert.AreEqual(208, ex.ErrorCode);
        Assert.IsTrue(ex.IsDeviceLocked);
    }

    [TestMethod]
    public void IsDeviceLocked_False_OnOtherErrorCodes()
    {
        Assert.IsFalse(new DeviceLinkServiceException(0, "ok").IsDeviceLocked);
        Assert.IsFalse(new DeviceLinkServiceException(11, "remote error").IsDeviceLocked);
        Assert.IsFalse(new DeviceLinkServiceException(207, "off-by-one").IsDeviceLocked);
        Assert.IsFalse(new DeviceLinkServiceException(209, "off-by-one").IsDeviceLocked);
    }

    [TestMethod]
    public void IsStrictSubtypeOfDeviceLinkException_SoExistingCatchBlocksStillCatchIt()
    {
        var ex = new DeviceLinkServiceException(208, "locked");

        // The whole point of the subtype: a caller that still only catches DeviceLinkException keeps
        // working unchanged, while a caller that wants the errno can match the more specific type.
        Assert.IsInstanceOfType(ex, typeof(DeviceLinkException));
        Assert.IsInstanceOfType(ex, typeof(NetimobiledeviceException));
    }
}
