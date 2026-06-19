using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;
using System.Reflection;

namespace NetimobiledeviceTest.Backup;

/// <summary>
/// Regression-guard tests that assert our fork-only customizations remain on the public/internal
/// API surface after upstream merges. These tests fail loudly if a future upstream merge silently
/// drops our additive properties.
/// </summary>
[TestClass]
public class ForkCustomizationRegressionTests
{
    [TestMethod]
    [Description("Asserts ShouldDiscardFile exists on DeviceLinkService (fork-only additive property)")]
    public void DeviceLinkService_ShouldDiscardFile_PropertyExists()
    {
        PropertyInfo? property = typeof(DeviceLinkService).GetProperty(
            "ShouldDiscardFile",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.IsNotNull(property,
            "DeviceLinkService.ShouldDiscardFile must exist. " +
            "This is a fork-only additive property (commit 2aac925). " +
            "If this test fails after an upstream merge, restore the property.");

        Assert.AreEqual(typeof(Func<string, bool>), property.PropertyType,
            "ShouldDiscardFile must be Func<string, bool>");

        Assert.IsTrue(property.CanRead && property.CanWrite,
            "ShouldDiscardFile must be publicly readable and writable");
    }

    [TestMethod]
    [Description("Asserts ShouldDiscardFile exists on Mobilebackup2Service (fork-only additive property)")]
    public void Mobilebackup2Service_ShouldDiscardFile_PropertyExists()
    {
        PropertyInfo? property = typeof(Mobilebackup2Service).GetProperty(
            "ShouldDiscardFile",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.IsNotNull(property,
            "Mobilebackup2Service.ShouldDiscardFile must exist. " +
            "This is a fork-only additive property. " +
            "If this test fails after an upstream merge, restore the property.");

        Assert.AreEqual(typeof(Func<string, bool>), property.PropertyType,
            "ShouldDiscardFile must be Func<string, bool>");
    }

    [TestMethod]
    [Description("Asserts LastBackupThroughputStats exists on Mobilebackup2Service (fork-only additive property)")]
    public void Mobilebackup2Service_LastBackupThroughputStats_PropertyExists()
    {
        PropertyInfo? property = typeof(Mobilebackup2Service).GetProperty(
            "LastBackupThroughputStats",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.IsNotNull(property,
            "Mobilebackup2Service.LastBackupThroughputStats must exist. " +
            "This is a fork-only additive property (commit 49fa8e5). " +
            "If this test fails after an upstream merge, restore the property.");

        Assert.IsTrue(property.CanRead,
            "LastBackupThroughputStats must be publicly readable");
    }

    [TestMethod]
    [Description("Asserts GetAndResetThroughputStats exists on DeviceLinkService (fork-only additive method)")]
    public void DeviceLinkService_GetAndResetThroughputStats_MethodExists()
    {
        MethodInfo? method = typeof(DeviceLinkService).GetMethod(
            "GetAndResetThroughputStats",
            BindingFlags.Public | BindingFlags.Instance);

        Assert.IsNotNull(method,
            "DeviceLinkService.GetAndResetThroughputStats must exist. " +
            "This is a fork-only additive method (commit 49fa8e5). " +
            "If this test fails after an upstream merge, restore the method.");
    }
}
