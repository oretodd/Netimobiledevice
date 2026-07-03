using System.Text;

namespace NetimobiledeviceTest.Backup;

/// <summary>
/// Fork regression tests for the Info.plist truncation data-corruption fix (#2199 P2-1).
///
/// Background: <c>Mobilebackup2Service.Backup</c> rewrote <c>Info.plist</c> every attempt with
/// <c>File.OpenWrite</c> — <c>FileMode.OpenOrCreate</c> WITHOUT truncation. When the newly-built plist
/// was SHORTER than the last one (e.g. an app was uninstalled, so its entry vanished), the stale tail
/// bytes after <c>&lt;/plist&gt;</c> survived on disk, handing the device a malformed plist. The fix
/// opens with <c>FileMode.Create</c>, which truncates to zero length first.
///
/// These tests exercise the EXACT two write shapes against the filesystem so the fix is pinned: the OLD
/// OpenWrite shape reproduces the corruption; the NEW FileMode.Create shape yields exactly the new bytes.
/// </summary>
[TestClass]
public class InfoPlistTruncationTests
{
    private static string CreateTempPath()
    {
        return Path.Combine(Path.GetTempPath(), $"nimd-2199-info-{Guid.NewGuid():N}.plist");
    }

    private static readonly byte[] LongerStalePlist =
        Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict><key>OldApp</key><string>lingering</string></dict></plist>");

    private static readonly byte[] ShorterNewPlist =
        Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict/></plist>");

    [TestMethod]
    [Description("#2199 P2-1: FileMode.Create truncates a longer stale Info.plist so a shorter rewrite yields EXACTLY the new bytes (no stale tail after </plist>).")]
    public void FileModeCreate_OverLongerStalePlist_YieldsExactlyNewBytes()
    {
        string path = CreateTempPath();
        try {
            // A longer plist left by a prior attempt (before an app was uninstalled).
            File.WriteAllBytes(path, LongerStalePlist);
            Assert.IsTrue(LongerStalePlist.Length > ShorterNewPlist.Length,
                "Precondition: the stale plist must be longer than the new one for the truncation case to matter.");

            // The NEW production write shape: FileMode.Create truncates first.
            using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write)) {
                fs.Write(ShorterNewPlist, 0, ShorterNewPlist.Length);
            }

            byte[] onDisk = File.ReadAllBytes(path);
            CollectionAssert.AreEqual(ShorterNewPlist, onDisk,
                "FileMode.Create must yield exactly the new (shorter) plist bytes — no stale tail survives (#2199 P2-1).");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [TestMethod]
    [Description("#2199 P2-1: the OLD File.OpenWrite (OpenOrCreate, no truncation) shape leaves a corrupting stale tail after </plist> — this is the bug the fix removes.")]
    public void OpenWrite_OverLongerStalePlist_LeavesCorruptingStaleTail()
    {
        string path = CreateTempPath();
        try {
            File.WriteAllBytes(path, LongerStalePlist);

            // The OLD production write shape: File.OpenWrite is FileMode.OpenOrCreate WITHOUT truncation,
            // so a shorter write overwrites only the leading bytes and leaves the stale tail.
            using (FileStream fs = File.OpenWrite(path)) {
                fs.Write(ShorterNewPlist, 0, ShorterNewPlist.Length);
            }

            byte[] onDisk = File.ReadAllBytes(path);
            Assert.AreEqual(LongerStalePlist.Length, onDisk.Length,
                "The un-truncated OpenWrite leaves the file at its OLD (longer) length — the corruption this fix removes.");
            string text = Encoding.UTF8.GetString(onDisk);
            Assert.IsTrue(text.IndexOf("</plist>", StringComparison.Ordinal) < text.Length - "</plist>".Length,
                "There must be a stale tail AFTER the new </plist> — proving the malformed-plist bug the fix eliminates.");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }
}
