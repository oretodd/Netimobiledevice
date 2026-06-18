using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// A persistent <c>_apple-mobdev2._tcp</c> browser backed by Apple's <c>mDNSResponder</c> daemon via
/// <c>dnssd.dll</c> (DNSServiceBrowse / DNSServiceResolve / DNSServiceGetAddrInfo) — the same library
/// <c>dns-sd.exe</c> uses.
///
/// <para>
/// This exists because the raw multicast-socket browser (<see cref="PersistentMdnsBrowser"/>) is
/// UNRELIABLE when a low-metric VPN (NordLynx) is up (ScribeHold #1924/#1925): with the VPN holding the
/// default route, Windows multicast delivery to our SO_REUSEADDR sockets becomes intermittent and the
/// physical Wi-Fi interface frequently receives ZERO device responses in a window where <c>dns-sd</c>
/// resolves every device on that same interface. Every raw-socket join variant tried (membership by
/// local address, by interface index, single Any-bound socket joined on all indices) was empirically
/// non-deterministic under VPN. The mDNSResponder daemon owns per-interface multicast at the OS level
/// and is not subject to that race, so it discovers + resolves reliably from a cold start with the VPN
/// up. When the daemon is present we use it; otherwise the caller falls back to the raw browser.
/// </para>
///
/// <para>
/// The daemon maintains the records; this class keeps live Browse/Resolve/GetAddrInfo operations open
/// and accumulates resolved instances in <see cref="MdnsRecordCache"/>-equivalent shape (a
/// <see cref="ServiceInstance"/> per advertised name, with its SRV host/port and IPv4 addresses).
/// </para>
/// </summary>
public sealed class DnsSdMobdev2Browser : IDisposable {
    private const string Lib = "dnssd.dll";
    private const string ServiceType = "_apple-mobdev2._tcp";
    private const uint kFlagsAdd = 0x2;
    private const uint kFlagsShareConnection = 0x4000; // kDNSServiceFlagsShareConnection
    private const uint kProtocolIPv4 = 0x1;
    private const int kErrorNoError = 0;

    private readonly ILogger _logger;
    private readonly object _lock = new();
    // Subordinate operation refs (browse/resolve/getaddrinfo) all share _connRef's socket via the
    // ShareConnection flag, so a SINGLE blocking DNSServiceProcessResult thread pumps everything — no
    // per-ref select (which proved unreliable on a background thread against this dnssd.dll).
    private readonly List<IntPtr> _subRefs = [];
    private readonly List<Delegate> _callbacks = []; // keep delegates alive against GC
    private readonly Dictionary<string, ResolvedInstance> _instances = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _hostAddrs = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread _pumpThread;
    private IntPtr _connRef;     // master shared connection (owns the socket the pump reads)
    private bool _started;

    private sealed class ResolvedInstance {
        public string Instance = "";
        public string Host = "";
        public ushort Port;
        public uint Interface;
    }

    public DnsSdMobdev2Browser(ILogger? logger = null) {
        _logger = logger ?? NullLogger.Instance;
        _pumpThread = new Thread(PumpLoop) { IsBackground = true, Name = "dnssd-mobdev2-pump" };
    }

    /// <summary>
    /// True if dnssd.dll is present and the mDNSResponder daemon accepts a connection (Bonjour/AMDS
    /// installed and running). Probed by opening and immediately closing a connection.
    /// </summary>
    public static bool IsAvailable() {
        try {
            int err = DNSServiceCreateConnection(out IntPtr sdRef);
            if (err == kErrorNoError && sdRef != IntPtr.Zero) {
                DNSServiceRefDeallocate(sdRef);
                return true;
            }
            return false;
        }
        catch (DllNotFoundException) { return false; }
        catch (Exception) { return false; }
    }

    /// <summary>Start the persistent browse. Safe to call once; subsequent calls are no-ops.</summary>
    public void Start() {
        lock (_lock) {
            if (_started) {
                return;
            }
            // Master shared connection: browse/resolve/getaddrinfo are all issued ON this ref with the
            // ShareConnection flag, so they multiplex over its single socket and one ProcessResult drains
            // them all.
            int connErr = DNSServiceCreateConnection(out _connRef);
            if (connErr != kErrorNoError || _connRef == IntPtr.Zero) {
                _logger.LogWarning("dnssd DNSServiceCreateConnection failed ({Err}); mobdev2 daemon browse unavailable", connErr);
                return;
            }

            BrowseReply browseCb = OnBrowse;
            _callbacks.Add(browseCb);
            IntPtr browseRef = _connRef; // in/out: shared-connection subordinate ref
            int err = DNSServiceBrowse(ref browseRef, kFlagsShareConnection, 0, ServiceType, null, browseCb, IntPtr.Zero);
            if (err != kErrorNoError) {
                _logger.LogWarning("dnssd DNSServiceBrowse failed ({Err}); mobdev2 daemon browse unavailable", err);
                DNSServiceRefDeallocate(_connRef);
                _connRef = IntPtr.Zero;
                return;
            }
            _subRefs.Add(browseRef);
            _started = true;
            _pumpThread.Start();
            _logger.LogInformation("mDNS mobdev2 browse started via dnssd.dll (mDNSResponder daemon)");
        }
    }

    /// <summary>The mobdev2 instances currently resolved (PTR+SRV+at least one IPv4 address).</summary>
    public List<ServiceInstance> Snapshot() {
        lock (_lock) {
            var result = new List<ServiceInstance>();
            foreach (ResolvedInstance inst in _instances.Values) {
                if (!_hostAddrs.TryGetValue(inst.Host, out List<string>? ips) || ips.Count == 0) {
                    continue;
                }
                var si = new ServiceInstance(inst.Instance) {
                    Host = inst.Host.TrimEnd('.'),
                    Port = inst.Port,
                    Addresses = ips.Distinct().Select(ip => new Address(ip, inst.Interface.ToString(System.Globalization.CultureInfo.InvariantCulture))).ToList()
                };
                result.Add(si);
            }
            return result;
        }
    }

    // --- dnssd callbacks ---------------------------------------------------------------------------

    private void OnBrowse(IntPtr sdRef, uint flags, uint iface, int err, string serviceName, string regtype, string domain, IntPtr ctx) {
        if (err != kErrorNoError || (flags & kFlagsAdd) == 0) {
            return;
        }
        // OBSERVATION-ONLY (#1936): L1/L2 dnssd-daemon browse-callback observation. Debug level; the
        // {Layer} field matches the Service-side diagnostic shape so the daemon path is queryable too.
        _logger.LogDebug("dnssd mobdev2 browse add: {Service} (if {Interface}) layer={Layer}", serviceName, iface, "L2_MdnsRx");
        ResolveReply resolveCb = OnResolve;
        lock (_lock) {
            _callbacks.Add(resolveCb);
            IntPtr rref = _connRef; // shared-connection subordinate ref
            if (DNSServiceResolve(ref rref, kFlagsShareConnection, iface, serviceName, regtype, domain, resolveCb, IntPtr.Zero) == kErrorNoError) {
                _subRefs.Add(rref);
            }
        }
    }

    private void OnResolve(IntPtr sdRef, uint flags, uint iface, int err, string fullname, string hostTarget, ushort port, ushort txtLen, IntPtr txt, IntPtr ctx) {
        if (err != kErrorNoError) {
            return;
        }
        ushort hostPort = (ushort)((port >> 8) | (port << 8)); // network -> host order
        // OBSERVATION-ONLY (#1936): L2 dnssd resolve-callback observation. Debug; queryable {Layer} field.
        _logger.LogDebug("dnssd mobdev2 resolve: {Service} -> {Host}:{Port} (if {Interface}) layer={Layer}",
            fullname, hostTarget, hostPort, iface, "L2_MdnsRx");
        lock (_lock) {
            _instances[fullname] = new ResolvedInstance { Instance = fullname, Host = hostTarget, Port = hostPort, Interface = iface };
            AddrReply addrCb = OnAddr;
            _callbacks.Add(addrCb);
            IntPtr aref = _connRef; // shared-connection subordinate ref
            if (DNSServiceGetAddrInfo(ref aref, kFlagsShareConnection, iface, kProtocolIPv4, hostTarget, addrCb, IntPtr.Zero) == kErrorNoError) {
                _subRefs.Add(aref);
            }
        }
    }

    private void OnAddr(IntPtr sdRef, uint flags, uint iface, int err, string hostname, IntPtr address, uint ttl, IntPtr ctx) {
        if (err != kErrorNoError || (flags & kFlagsAdd) == 0 || address == IntPtr.Zero) {
            return;
        }
        // sockaddr: sa_family (2 bytes) at offset 0; AF_INET == 2; IPv4 bytes at offset 4..7.
        short family = Marshal.ReadInt16(address);
        if (family != 2) {
            return;
        }
        byte[] ip = new byte[4];
        Marshal.Copy(address + 4, ip, 0, 4);
        string ipStr = new IPAddress(ip).ToString();
        lock (_lock) {
            if (!_hostAddrs.TryGetValue(hostname, out List<string>? list)) {
                list = [];
                _hostAddrs[hostname] = list;
            }
            if (!list.Contains(ipStr)) {
                list.Add(ipStr);
                // OBSERVATION-ONLY (#1936): L2 dnssd getaddrinfo-callback observation. Debug; {Layer} field.
                _logger.LogDebug("dnssd mobdev2 addr: {Host} -> {Ip} (if {Interface}) layer={Layer}", hostname, ipStr, iface, "L2_MdnsRx");
            }
        }
    }

    private void PumpLoop() {
        // ONE blocking pump on the shared connection's socket. All browse/resolve/getaddrinfo replies
        // multiplex over _connRef (ShareConnection), so a single DNSServiceProcessResult drains them all.
        // ProcessResult blocks until a reply is ready (the documented usage), which avoids the fragile
        // per-ref select that did not work from a background thread against this dnssd.dll.
        IntPtr conn;
        lock (_lock) {
            conn = _connRef;
        }
        if (conn == IntPtr.Zero) {
            return;
        }
        try {
            while (!_cts.IsCancellationRequested) {
                int err;
                try {
                    err = DNSServiceProcessResult(conn);
                }
                catch (Exception ex) {
                    _logger.LogDebug(ex, "dnssd DNSServiceProcessResult threw; ending pump");
                    break;
                }
                if (err != kErrorNoError) {
                    // Non-zero usually means the connection was deallocated (shutdown) — exit cleanly.
                    _logger.LogDebug("dnssd pump: ProcessResult returned {Err}; ending pump", err);
                    break;
                }
            }
        }
        catch (Exception ex) {
            _logger.LogDebug(ex, "dnssd pump loop ended");
        }
    }

    public void Dispose() {
        _cts.Cancel();
        try {
            if (_pumpThread.IsAlive) {
                _pumpThread.Join(TimeSpan.FromSeconds(2));
            }
        }
        catch {
            // pump shutting down
        }
        lock (_lock) {
            // Deallocating the master shared connection frees all subordinate browse/resolve/getaddrinfo
            // refs with it, and closes the socket the pump blocks on (so DNSServiceProcessResult returns).
            if (_connRef != IntPtr.Zero) {
                try {
                    DNSServiceRefDeallocate(_connRef);
                }
                catch {
                    // best effort
                }
                _connRef = IntPtr.Zero;
            }
            _subRefs.Clear();
            _callbacks.Clear();
        }
        _cts.Dispose();
    }

    // --- P/Invoke ---------------------------------------------------------------------------------
    //
    // Shared-connection model: browse/resolve/getaddrinfo take `ref IntPtr sdRef` (in = the master
    // connection, with kDNSServiceFlagsShareConnection; out = the subordinate ref). dnssd.dll strings are
    // UTF-8 char*, marshalled as LPUTF8Str outbound. Inbound callback string params stay default `string`
    // — that is the shape proven to fire against this dnssd.dll (LPUTF8Str on the delegate params silently
    // suppressed callbacks in testing); mobdev2 names are ASCII so this is lossless.
#pragma warning disable CA2101 // P/Invoke string marshaling handled via LPUTF8Str on the extern signatures
    private delegate void BrowseReply(IntPtr sdRef, uint flags, uint iface, int err,
        string serviceName, string regtype, string replyDomain, IntPtr ctx);
    private delegate void ResolveReply(IntPtr sdRef, uint flags, uint iface, int err,
        string fullname, string hostTarget, ushort port, ushort txtLen, IntPtr txt, IntPtr ctx);
    private delegate void AddrReply(IntPtr sdRef, uint flags, uint iface, int err,
        string hostname, IntPtr address, uint ttl, IntPtr ctx);

    [DllImport(Lib)]
    private static extern int DNSServiceCreateConnection(out IntPtr sdRef);
    [DllImport(Lib)]
    private static extern int DNSServiceBrowse(ref IntPtr sdRef, uint flags, uint iface,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string regtype, [MarshalAs(UnmanagedType.LPUTF8Str)] string? domain, BrowseReply cb, IntPtr ctx);
    [DllImport(Lib)]
    private static extern int DNSServiceResolve(ref IntPtr sdRef, uint flags, uint iface,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string regtype,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string domain, ResolveReply cb, IntPtr ctx);
    [DllImport(Lib)]
    private static extern int DNSServiceGetAddrInfo(ref IntPtr sdRef, uint flags, uint iface, uint protocol,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string hostname, AddrReply cb, IntPtr ctx);
    [DllImport(Lib)]
    private static extern int DNSServiceProcessResult(IntPtr sdRef);
    [DllImport(Lib)]
    private static extern void DNSServiceRefDeallocate(IntPtr sdRef);
#pragma warning restore CA2101
}
