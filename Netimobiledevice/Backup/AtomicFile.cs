using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Backup;

/// <summary>
/// ScribeHold fork (#2198, P1-3): atomic whole-file writes for backup metadata plists
/// (<c>Status.plist</c> and friends). A plain <c>File.WriteAllBytes</c> that is interrupted mid-write
/// (process kill, power loss, disk hiccup) leaves a TORN file on disk; a torn <c>Status.plist</c> then
/// poisons the next incremental attempt — the snapshot-integrity failure mode that ends in a silent
/// full re-transfer. The write goes to a sibling temp file first and is then moved over the target with
/// <see cref="File.Move(string, string, bool)"/> (MoveFileEx REPLACE_EXISTING — atomic on the same NTFS
/// volume), so the target path only ever contains either the complete old bytes or the complete new
/// bytes, never a partial. PUBLIC so the hosting ScribeHold.Service reuses the same canonical
/// implementation (one atomic-write, not two drifting copies).
/// </summary>
public static class AtomicFile
{
    /// <summary>
    /// Atomically replace (or create) <paramref name="path"/> with <paramref name="bytes"/>.
    /// The temp file is written beside the target (same volume — a cross-volume move would lose
    /// atomicity) and cleaned up best-effort on failure.
    /// </summary>
    public static async Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(bytes);

        string tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
        try {
            await File.WriteAllBytesAsync(tempPath, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, path, overwrite: true);
        }
        catch {
            TryDeleteTemp(tempPath);
            throw;
        }
    }

    /// <summary>
    /// Synchronous variant of <see cref="WriteAllBytesAsync"/> for callers on a sync path.
    /// </summary>
    public static void WriteAllBytes(string path, byte[] bytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(bytes);

        string tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
        try {
            File.WriteAllBytes(tempPath, bytes);
            File.Move(tempPath, path, overwrite: true);
        }
        catch {
            TryDeleteTemp(tempPath);
            throw;
        }
    }

    private static void TryDeleteTemp(string tempPath)
    {
        try {
            if (File.Exists(tempPath)) {
                File.Delete(tempPath);
            }
        }
        catch {
            // Best-effort cleanup — the atomic guarantee is about the TARGET path; a stray temp file is
            // harmless (unique name per write) and must never mask the original failure.
        }
    }
}
