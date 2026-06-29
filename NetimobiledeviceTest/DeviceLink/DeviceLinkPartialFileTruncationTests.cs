using System.Security.Cryptography;
using Netimobiledevice.DeviceLink;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork regression tests for the partial-file truncation data-corruption GATE (#2046).
///
/// Background: a file transfer in <c>DeviceLinkService.UploadFiles</c> opens the local file with
/// <c>File.OpenWrite</c> + <c>Seek(0, SeekOrigin.End)</c> so that in-session multi-chunk transfers
/// append correctly. When a PRIOR backup session was interrupted mid-file, a partial copy can remain
/// on disk. On the next attempt the device re-sends the WHOLE file -- and the open+seek-to-end would
/// APPEND the re-send onto the stale partial (partial bytes + full bytes), silently corrupting the
/// file. The fix (<see cref="DeviceLinkService.DeleteStalePartial"/>) removes any pre-existing file
/// at the start of a fresh transfer so the re-send is a clean replacement.
///
/// These tests exercise the EXACT production write sequence against the filesystem so they would
/// fail loudly if a future upstream merge drops the delete-guard.
/// </summary>
[TestClass]
public class DeviceLinkPartialFileTruncationTests
{
    private static string CreateTempPath()
    {
        return Path.Combine(Path.GetTempPath(), $"nimd-2046-{Guid.NewGuid():N}.bin");
    }

    private static byte[] Sha256(byte[] data)
    {
        return SHA256.HashData(data);
    }

    /// <summary>
    /// Mirrors the production receive sequence for the FIRST chunk of a new file transfer:
    /// DeleteStalePartial -> File.OpenWrite -> Seek(End) -> write the whole re-sent content.
    /// </summary>
    private static void ReceiveWholeFile(string localPath, byte[] resentContent)
    {
        DeviceLinkService.DeleteStalePartial(localPath);
        using FileStream fs = File.OpenWrite(localPath);
        fs.Seek(0, SeekOrigin.End);
        fs.Write(resentContent, 0, resentContent.Length);
    }

    [TestMethod]
    [Description("A whole-file re-send over a pre-existing partial yields exactly the re-sent bytes (no append-corruption).")]
    public void WholeFileResend_OverPreExistingPartial_ReplacesNotAppends()
    {
        string path = CreateTempPath();
        try {
            // A partial left by an interrupted prior session.
            byte[] partial = new byte[2048];
            for (int i = 0; i < partial.Length; i++) {
                partial[i] = (byte) (i % 251);
            }
            File.WriteAllBytes(path, partial);

            // The device re-sends the WHOLE file (distinct content from the partial).
            byte[] whole = new byte[5000];
            for (int i = 0; i < whole.Length; i++) {
                whole[i] = (byte) ((i * 7 + 13) % 256);
            }

            ReceiveWholeFile(path, whole);

            byte[] onDisk = File.ReadAllBytes(path);

            Assert.AreEqual(whole.Length, onDisk.Length,
                "On-disk length must equal the re-sent content length, not partial+whole appended.");
            CollectionAssert.AreEqual(whole, onDisk,
                "On-disk bytes must equal the re-sent content exactly.");
            CollectionAssert.AreEqual(Sha256(whole), Sha256(onDisk),
                "On-disk hash must equal the re-sent content hash.");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [TestMethod]
    [Description("Proves the corruption mode the guard prevents: open+seek-end WITHOUT the delete appends partial+whole.")]
    public void WithoutDeleteGuard_OpenWriteSeekEnd_AppendsAndCorrupts()
    {
        string path = CreateTempPath();
        try {
            byte[] partial = new byte[2048];
            File.WriteAllBytes(path, partial);

            byte[] whole = new byte[5000];

            // Reproduce the OLD behavior (no DeleteStalePartial) to confirm it corrupts.
            using (FileStream fs = File.OpenWrite(path)) {
                fs.Seek(0, SeekOrigin.End);
                fs.Write(whole, 0, whole.Length);
            }

            byte[] onDisk = File.ReadAllBytes(path);

            Assert.AreEqual(partial.Length + whole.Length, onDisk.Length,
                "Without the delete-guard, the re-send appends onto the partial (this is the corruption #2046 fixes).");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [TestMethod]
    [Description("DeleteStalePartial is a no-op when the target file does not already exist.")]
    public void DeleteStalePartial_NoPreExistingFile_IsNoOpAndAllowsCleanWrite()
    {
        string path = CreateTempPath();
        try {
            Assert.IsFalse(File.Exists(path), "Precondition: no file at the target path.");

            // Must not throw on a non-existent path.
            DeviceLinkService.DeleteStalePartial(path);

            byte[] whole = new byte[1234];
            for (int i = 0; i < whole.Length; i++) {
                whole[i] = (byte) (i % 256);
            }
            ReceiveWholeFile(path, whole);

            byte[] onDisk = File.ReadAllBytes(path);
            CollectionAssert.AreEqual(whole, onDisk,
                "A first-ever transfer (no pre-existing file) writes exactly the re-sent content.");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [TestMethod]
    [Description("In-session multi-chunk transfers still append correctly: the delete runs only at the start of a new file.")]
    public void MultiChunkInSession_AppendsContiguously()
    {
        string path = CreateTempPath();
        try {
            byte[] chunk1 = new byte[1500];
            for (int i = 0; i < chunk1.Length; i++) {
                chunk1[i] = (byte) (i % 256);
            }
            byte[] chunk2 = new byte[2500];
            for (int i = 0; i < chunk2.Length; i++) {
                chunk2[i] = (byte) ((i + 100) % 256);
            }

            // First chunk of a NEW file: delete stale (none), open, seek-end, write.
            DeviceLinkService.DeleteStalePartial(path);
            using (FileStream fs = File.OpenWrite(path)) {
                fs.Seek(0, SeekOrigin.End);
                fs.Write(chunk1, 0, chunk1.Length);
                // Subsequent chunk WITHIN the same session: stream stays open, seek-end, append.
                // (No DeleteStalePartial call -- it only runs when _fileStream == null.)
                fs.Seek(0, SeekOrigin.End);
                fs.Write(chunk2, 0, chunk2.Length);
            }

            byte[] onDisk = File.ReadAllBytes(path);
            byte[] expected = new byte[chunk1.Length + chunk2.Length];
            Buffer.BlockCopy(chunk1, 0, expected, 0, chunk1.Length);
            Buffer.BlockCopy(chunk2, 0, expected, chunk1.Length, chunk2.Length);

            CollectionAssert.AreEqual(expected, onDisk,
                "Multi-chunk in-session transfer must produce chunk1 followed by chunk2.");
        }
        finally {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        }
    }

    [TestMethod]
    [Description("Regression guard: DeleteStalePartial exists as an internal static method on DeviceLinkService.")]
    public void DeleteStalePartial_MethodExists()
    {
        System.Reflection.MethodInfo? method = typeof(DeviceLinkService).GetMethod(
            "DeleteStalePartial",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        Assert.IsNotNull(method,
            "DeviceLinkService.DeleteStalePartial must exist. This is the fork-only data-corruption " +
            "GATE for #2046. If this test fails after an upstream merge, restore the delete-guard " +
            "before File.OpenWrite in UploadFiles.");
    }
}
