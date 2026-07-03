using Netimobiledevice.Afc;
using Netimobiledevice.NotificationProxy;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Backup;

internal sealed class BackupLock(AfcService afc, NotificationProxyService np) : IDisposable
{
    private const string SYNC_LOCK_FILE_PATH = "/com.apple.itunes.lock_sync";

    private readonly AfcService _afc = afc;
    private readonly NotificationProxyService _np = np;

    private ulong _syncLockFileHandle;

    public void Dispose()
    {
        // #2199 (P2-2): bound the whole unlock/close/post teardown with a 5s CTS and swallow on timeout.
        // The prior sequence ran AFC Unlock + FileClose via sync-over-async on CancellationToken.None —
        // each op waited its OWN read timeout against a possibly-dead socket, so a wedged device stalled
        // Dispose (and the resume behind it) for minutes. The device invalidates the sync lock itself when
        // the connection drops, so on a timeout we can safely stop waiting; still post SyncDidFinish so a
        // live device that IS reachable gets the release signal.
        using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            Task.Run(async () => {
                await _afc.Lock(_syncLockFileHandle, AfcLockModes.Unlock, cts.Token).ConfigureAwait(false);
                await _afc.FileClose(_syncLockFileHandle, cts.Token).ConfigureAwait(false);
            }, cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) {
            // The 5s teardown bound elapsed against a wedged/dead socket — stop waiting. iOS invalidates
            // the sync lock on the connection drop, so the on-device lock is released regardless.
        }
        catch (Exception) {
            // Any other AFC/transport failure during best-effort teardown is non-fatal — the socket close
            // releases the transport and iOS drops the lock on disconnect.
        }
        try {
            _np.Post(SendableNotificaton.SyncDidFinish);
        }
        catch (Exception) {
            // Best-effort notification on a possibly-dead notification-proxy socket; never fatal on teardown.
        }
    }

    public async Task AquireBackupLock(CancellationToken cancellationToken)
    {
        await _np.PostAsync(SendableNotificaton.SyncWillStart).ConfigureAwait(false);
        _syncLockFileHandle = await _afc.FileOpen(SYNC_LOCK_FILE_PATH, cancellationToken, AfcFileOpenMode.ReadWrite).ConfigureAwait(false);
        if (_syncLockFileHandle > 0) {
            await _np.PostAsync(SendableNotificaton.SyncLockRequest).ConfigureAwait(false);

            bool lockAquired = false;
            for (int i = 0; i < 50; i++) {
                try {
                    await _afc.Lock(_syncLockFileHandle, AfcLockModes.ExclusiveLock, cancellationToken).ConfigureAwait(false);
                    lockAquired = true;
                    break;
                }
                catch (AfcException e) {
                    if (e.AfcError == AfcError.OpWouldBlock) {
                        await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                    }
                    else {
                        await _afc.FileClose(_syncLockFileHandle, cancellationToken).ConfigureAwait(false);
                        throw;
                    }
                }
                catch (Exception) {
                    throw;
                }
            }

            if (lockAquired) {
                await _np.PostAsync(SendableNotificaton.SyncDidStart).ConfigureAwait(false);
            }
        }
        else {
            throw new AfcException("Failed to get file handle for iTunes backup sync file");
        }
    }
}
