using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// mDNS browser returning data classes with per-address interface names.
/// Works for any DNS-SD type, e.g. "_remoted._tcp.local."
/// </summary>
public static class BonjourService {
    private const string MOBDEV2_SERVICE_NAME = "_apple-mobdev2._tcp.local.";
    private const string REMOTED_SERVICE_NAME = "_remoted._tcp.local.";
    private const string REMOTEPAIRING_SERVICE_NAME = "_remotepairing._tcp.local.";
    private const string REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAME = "_remotepairing-manual-pairing._tcp.local.";

#if WINDOWS
    public const int DEFAULT_BONJOUR_TIMEOUT = 2000;
#else
    public const int DEFAULT_BONJOUR_TIMEOUT = 1000;
#endif

    // The mobdev2 discovery path is POLLED on an interval (ScribeHold's WiFi detector sweeps every ~5s).
    // A fresh open-listen-close browser per sweep discarded records between sweeps and left the socket
    // idle ~3s of every interval, so a device whose PTR/SRV/A arrived across sweeps never resolved
    // (ScribeHold #1914 round 7). A single persistent browser receives continuously and accumulates
    // records across sweeps; each BrowseMobdev2Async call just reads the latest resolved set.
    private static readonly object _mobdev2Lock = new();
    private static PersistentMdnsBrowser? _mobdev2Browser;
    private static bool _mobdev2Primed;

    public static async Task<List<ServiceInstance>> BrowseMobdev2Async(int timeout = DEFAULT_BONJOUR_TIMEOUT, ILogger? logger = null) {
        bool justCreated = false;
        PersistentMdnsBrowser browser;
        lock (_mobdev2Lock) {
            if (_mobdev2Browser is null) {
                _mobdev2Browser = new PersistentMdnsBrowser(MOBDEV2_SERVICE_NAME, logger);
                justCreated = true;
            }
            browser = _mobdev2Browser;
        }

        // On the very first sweep the cache is empty because the background loop has only just started.
        // Give it the caller's timeout window to accumulate an initial round of responses before reading,
        // so the first poll after service start can already surface a device rather than always returning
        // empty until the second poll. Steady-state sweeps read immediately (continuous receive already
        // populated the cache between polls).
        if (justCreated || !_mobdev2Primed) {
            await Task.Delay(timeout).ConfigureAwait(false);
            _mobdev2Primed = true;
        }

        return browser.SweepAsync();
    }

    /// <summary>
    /// Tear down the persistent mobdev2 browser (closes its sockets and stops the receive loop). Safe to
    /// call when no browser exists. The next <see cref="BrowseMobdev2Async"/> recreates it.
    /// </summary>
    public static async Task StopMobdev2BrowsingAsync() {
        PersistentMdnsBrowser? browser;
        lock (_mobdev2Lock) {
            browser = _mobdev2Browser;
            _mobdev2Browser = null;
            _mobdev2Primed = false;
        }
        if (browser is not null) {
            await browser.DisposeAsync().ConfigureAwait(false);
        }
    }

    public static async Task<List<ServiceInstance>> BrowseRemotedAsync(int timeout = DEFAULT_BONJOUR_TIMEOUT, ILogger? logger = null) {
        MdnsBrowser mdnsBrowser = new(logger);
        return await mdnsBrowser.BrowseService(REMOTED_SERVICE_NAME, timeout).ConfigureAwait(false);
    }

    public static async Task<List<ServiceInstance>> BrowseRemotePairingAsync(int timeout = DEFAULT_BONJOUR_TIMEOUT, ILogger? logger = null) {
        MdnsBrowser mdnsBrowser = new(logger);
        return await mdnsBrowser.BrowseService(REMOTEPAIRING_SERVICE_NAME, timeout).ConfigureAwait(false);
    }

    public static async Task<List<ServiceInstance>> BrowseRemotePairingManual(int timeout = DEFAULT_BONJOUR_TIMEOUT, ILogger? logger = null) {
        MdnsBrowser mdnsBrowser = new(logger);
        return await mdnsBrowser.BrowseService(REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAME, timeout).ConfigureAwait(false);
    }
}
