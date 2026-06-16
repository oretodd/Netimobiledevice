using System;

namespace Netimobiledevice.Remoted.Bonjour;

public class Address(string ip, string @interface) {
    public string Ip { get; set; } = ip;
    /// <summary>
    /// Local interface name (e.g., "en0"), or None if unknown
    /// </summary>
    public string Interface { get; set; } = @interface;

    public string FullIp {
        get {
            // A link-local IPv6 address (fe80::) is unroutable without a zone index, so append "%<zone>".
            // Guard against an empty zone — "fe80::...%" is invalid and worse than the bare address
            // (ScribeHold #1914). Interface carries the zone token (the interface index on Windows).
            if (!string.IsNullOrEmpty(Interface) && Ip.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)) {
                return $"{Ip}%{Interface}";
            }
            return Ip;
        }
    }
}
