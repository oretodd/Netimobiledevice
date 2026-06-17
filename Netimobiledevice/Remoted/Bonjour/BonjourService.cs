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
    private static DnsSdMobdev2Browser? _dnsSdBrowser;
    private static bool _mobdev2Primed;

    public static async Task<List<ServiceInstance>> BrowseMobdev2Async(int timeout = DEFAULT_BONJOUR_TIMEOUT, ILogger? logger = null) {
        bool justCreated = false;

        // Prefer the mDNSResponder daemon (dnssd.dll) when it is installed: with a low-metric VPN up, the
        // raw multicast-socket browser receives device responses on the Wi-Fi interface only
        // intermittently (Windows multicast delivery to our SO_REUSEADDR sockets is non-deterministic
        // under VPN — ScribeHold #1925), while the daemon resolves every device on that interface
        // reliably from a cold start. We fall back to the raw PersistentMdnsBrowser only when the daemon
        // is unavailable (Bonjour/AMDS not installed), preserving discovery on machines without it.
        DnsSdMobdev2Browser? dnsSd = null;
        PersistentMdnsBrowser? rawBrowser = null;
        lock (_mobdev2Lock) {
            if (_dnsSdBrowser is null && _mobdev2Browser is null) {
                if (DnsSdMobdev2Browser.IsAvailable()) {
                    _dnsSdBrowser = new DnsSdMobdev2Browser(logger);
                    _dnsSdBrowser.Start();
                }
                else {
                    logger?.LogInformation("dnssd.dll unavailable; using raw multicast mobdev2 browser");
                    _mobdev2Browser = new PersistentMdnsBrowser(MOBDEV2_SERVICE_NAME, logger);
                }
                justCreated = true;
            }
            dnsSd = _dnsSdBrowser;
            rawBrowser = _mobdev2Browser;
        }

        // On the very first sweep the daemon/cache has only just started; give it the caller's timeout
        // window to accumulate an initial round of responses before reading, so the first poll after
        // service start can already surface a device. Steady-state sweeps read immediately.
        if (justCreated || !_mobdev2Primed) {
            await Task.Delay(timeout).ConfigureAwait(false);
            _mobdev2Primed = true;
        }

        return dnsSd is not null ? dnsSd.Snapshot() : rawBrowser!.SweepAsync();
    }

    /// <summary>
    /// Tear down the persistent mobdev2 browser(s) (daemon browse and/or raw sockets). Safe to call when
    /// none exist. The next <see cref="BrowseMobdev2Async"/> recreates the appropriate one.
    /// </summary>
    public static async Task StopMobdev2BrowsingAsync() {
        PersistentMdnsBrowser? browser;
        DnsSdMobdev2Browser? dnsSd;
        lock (_mobdev2Lock) {
            browser = _mobdev2Browser;
            dnsSd = _dnsSdBrowser;
            _mobdev2Browser = null;
            _dnsSdBrowser = null;
            _mobdev2Primed = false;
        }
        dnsSd?.Dispose();
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
