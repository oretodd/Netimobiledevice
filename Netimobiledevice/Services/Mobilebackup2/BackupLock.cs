using Netimobiledevice.NotificationProxy;
using Netimobiledevice.Services.Afc;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Services.Mobilebackup2;

internal sealed class BackupLock : IAsyncDisposable {
    private const string SyncLockFilePath = "/com.apple.itunes.lock_sync";

    private readonly AfcService _afc;
    private readonly ulong? _lockFileHandle;
    private readonly NotificationProxyService _notificationProxy;

    private BackupLock(
        AfcService afc,
        NotificationProxyService notificationProxy,
        ulong? lockfileHandle
    ) {
        _afc = afc;
        _notificationProxy = notificationProxy;
        _lockFileHandle = lockfileHandle;
    }

    internal static async Task<BackupLock> Create(
        AfcService afc,
        NotificationProxyService notificationProxy,
        CancellationToken ct
    ) {
        await notificationProxy.NotifyPostAsync(SendableNotificaton.SyncWillStart, ct).ConfigureAwait(false);

        ulong lockfile = await afc.FileOpenAsync(SyncLockFilePath, AfcFileOpenMode.ReadWrite, ct).ConfigureAwait(false);
        if (lockfile != 0) {
            await notificationProxy.NotifyPostAsync(SendableNotificaton.SyncLockRequest, ct).ConfigureAwait(false);

            bool locked = false;
            for (int attempt = 0; attempt < 50; attempt++) {
                try {
                    await afc.LockAsync(lockfile, AfcLockModes.ExclusiveLock, ct).ConfigureAwait(false);
                }
                catch (AfcException e) when (e.Status == AfcError.OpWouldBlock) {
                    await Task.Delay(TimeSpan.FromMilliseconds(200), ct).ConfigureAwait(false);
                    continue;
                }
                catch (AfcException) {
                    await afc.FileCloseAsync(lockfile, ct).ConfigureAwait(false);
                    throw;
                }

                await notificationProxy.NotifyPostAsync(SendableNotificaton.SyncDidStart, ct).ConfigureAwait(false);
                locked = true;
                break;
            }

            if (!locked) {
                await afc.FileCloseAsync(lockfile, ct).ConfigureAwait(false);
                throw new AfcException("Failed to lock itunes sync file");
            }
        }
        return new BackupLock(afc, notificationProxy, lockfile);
    }

    public async ValueTask DisposeAsync() {
        // The device drops the sync lock itself when the connection goes, so a dead socket must not stall teardown.
        using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            if (_lockFileHandle is not null) {
                await _afc.LockAsync(_lockFileHandle.Value, AfcLockModes.Unlock, cts.Token).ConfigureAwait(false);
                await _afc.FileCloseAsync(_lockFileHandle.Value, cts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception) {
        }
        try {
            using CancellationTokenSource postCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _notificationProxy.NotifyPostAsync(SendableNotificaton.SyncDidFinish, postCts.Token).ConfigureAwait(false);
        }
        catch (Exception) {
        }
    }
}
