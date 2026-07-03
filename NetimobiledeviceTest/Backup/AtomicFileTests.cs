using Netimobiledevice.Backup;

namespace NetimobiledeviceTest.Backup;

/// <summary>
/// Fork tests for the atomic plist write (#2198, P1-3c).
///
/// Background: <c>Status.plist</c> was written with a plain <c>File.WriteAllBytes</c>; an interrupted
/// write (process kill, power loss) left a TORN file that poisoned the next incremental attempt — a
/// snapshot-integrity failure that ends in a silent full re-transfer. <see cref="AtomicFile"/> writes
/// to a sibling temp file and move-overwrites the target, so the target only ever holds either the
/// complete old bytes or the complete new bytes.
/// </summary>
[TestClass]
public class AtomicFileTests
{
    private string _dir = string.Empty;

    [TestInitialize]
    public void Setup()
    {
        _dir = Path.Combine(Path.GetTempPath(), "NetimobiledeviceTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [TestMethod]
    [Description("#2198 P1-3c: a fresh write creates the target with the exact bytes and leaves no temp file behind.")]
    public async Task Write_CreatesTarget_NoTempResidue()
    {
        string path = Path.Combine(_dir, "Status.plist");
        byte[] bytes = [1, 2, 3, 4, 5];

        await AtomicFile.WriteAllBytesAsync(path, bytes);

        CollectionAssert.AreEqual(bytes, await File.ReadAllBytesAsync(path));
        Assert.AreEqual(1, Directory.GetFiles(_dir).Length,
            "The temp file must be gone after a successful write (moved over the target).");
    }

    [TestMethod]
    [Description("#2198 P1-3c: overwriting an existing target replaces it completely (temp + move-overwrite).")]
    public async Task Write_OverwritesExistingTarget()
    {
        string path = Path.Combine(_dir, "Status.plist");
        await File.WriteAllBytesAsync(path, [9, 9, 9, 9, 9, 9, 9, 9]);

        byte[] replacement = [1, 2, 3];
        await AtomicFile.WriteAllBytesAsync(path, replacement);

        CollectionAssert.AreEqual(replacement, await File.ReadAllBytesAsync(path),
            "The target must hold exactly the new bytes — no stale tail from the longer prior content.");
    }

    [TestMethod]
    [Description("#2198 P1-3c (failing-shape repro): when the final move fails (target locked), the target keeps its COMPLETE original content — never a partial — and the temp file is cleaned up.")]
    public async Task Write_FailedReplace_LeavesTargetIntact_NoPartial()
    {
        string path = Path.Combine(_dir, "Status.plist");
        byte[] original = [7, 7, 7, 7];
        await File.WriteAllBytesAsync(path, original);

        // Lock the target so the move-overwrite fails — the simulated failure point. Windows surfaces
        // the sharing violation as UnauthorizedAccessException (or IOException depending on the lock
        // shape); either way the WRITE must fail and the target must stay intact.
        using (FileStream lockStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) {
            Exception ex = await Assert.ThrowsAsync<Exception>(
                () => AtomicFile.WriteAllBytesAsync(path, [1, 2, 3, 4, 5, 6, 7, 8]));
            Assert.IsTrue(ex is IOException or UnauthorizedAccessException,
                $"A locked target must fail the atomic write with an IO-class exception, got {ex.GetType().Name}.");
        }

        CollectionAssert.AreEqual(original, await File.ReadAllBytesAsync(path),
            "A failed atomic write must leave the prior COMPLETE content on the target — the whole point is that no failure mode can produce a torn/partial file.");
        Assert.AreEqual(1, Directory.GetFiles(_dir).Length,
            "The temp file must be cleaned up best-effort after the failed move.");
    }

    [TestMethod]
    [Description("#2198 P1-3c: the synchronous variant has the same atomic semantics.")]
    public void WriteSync_CreatesTarget_NoTempResidue()
    {
        string path = Path.Combine(_dir, "Status.plist");
        byte[] bytes = [42, 42];

        AtomicFile.WriteAllBytes(path, bytes);

        CollectionAssert.AreEqual(bytes, File.ReadAllBytes(path));
        Assert.AreEqual(1, Directory.GetFiles(_dir).Length);
    }

    [TestMethod]
    [Description("#2198 P1-3c: argument validation — null/empty path and null bytes are rejected.")]
    public async Task Write_ValidatesArguments()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => AtomicFile.WriteAllBytesAsync(string.Empty, [1]));
        await Assert.ThrowsAsync<ArgumentNullException>(() => AtomicFile.WriteAllBytesAsync(Path.Combine(_dir, "x"), null!));
    }
}
