using Microsoft.Extensions.Logging.Abstractions;
using Netimobiledevice.Backup;

namespace NetimobiledeviceTest.Backup;

[TestClass]
public class ManifestEscalationTests
{
    private string _manifestPath = null!;

    [TestInitialize]
    public void Init() => _manifestPath = Path.Combine(Path.GetTempPath(), $"nimd-3197-{Guid.NewGuid():N}.plist");

    [TestCleanup]
    public void Cleanup() => File.Delete(_manifestPath);

    [TestMethod]
    public void IncrementalWithoutManifest_RunsFull()
    {
        Assert.IsTrue(Mobilebackup2Service.PrepareManifestForBackup(_manifestPath, false, NullLogger.Instance));
    }

    [TestMethod]
    public void IncrementalWithManifest_StaysIncremental()
    {
        File.WriteAllText(_manifestPath, "x");

        Assert.IsFalse(Mobilebackup2Service.PrepareManifestForBackup(_manifestPath, false, NullLogger.Instance));
        Assert.IsTrue(File.Exists(_manifestPath));
    }

    [TestMethod]
    public void FullWithManifest_RunsFullAndDeletesManifest()
    {
        File.WriteAllText(_manifestPath, "x");

        Assert.IsTrue(Mobilebackup2Service.PrepareManifestForBackup(_manifestPath, true, NullLogger.Instance));
        Assert.IsFalse(File.Exists(_manifestPath));
    }
}
