using System.Collections.Generic;

namespace Netimobiledevice.Remoted.Bonjour;

/// <summary>
/// Where the mDNS packet parser deposits the records it extracts. Decoupling the parser from storage lets
/// the same parse path feed two very different accumulators: a per-sweep sink for the one-shot
/// <c>BrowseService</c> callers (RemoteD/Tunneld), and the cross-sweep <see cref="MdnsRecordCache"/> that
/// the persistent mobdev2 browser uses to resolve a device whose PTR/SRV/A records arrive in separate
/// sweeps (ScribeHold #1914 round 7).
/// </summary>
public interface IMdnsRecordSink {
    /// <summary>A PTR record: <paramref name="serviceType"/> points at the instance <paramref name="target"/>.</summary>
    void AddPtr(string serviceType, string target, uint ttl);

    /// <summary>An SRV record for <paramref name="instance"/> (its target host + port).</summary>
    void AddSrv(string instance, Service service, uint ttl);

    /// <summary>A TXT record for <paramref name="instance"/>.</summary>
    void AddTxt(string instance, Dictionary<string, string> properties, uint ttl);

    /// <summary>An A/AAAA record: <paramref name="host"/> resolves to <paramref name="address"/>.</summary>
    void AddAddress(string host, Address address, uint ttl);

    /// <summary>One packet failed to parse. Counters surface a parse-side failure separately from "no packets".</summary>
    void RecordParseFailure();
}
