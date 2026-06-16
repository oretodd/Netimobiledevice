using Microsoft.Extensions.Logging;
using Netimobiledevice.Lockdown;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Tests for the pair-record reading portion of
/// <see cref="LockdownService.GetMobdev2Lockdowns(string, string, bool, int, Microsoft.Extensions.Logging.ILogger)"/>.
/// Regression guard for ScribeHold #1901: a pair record (<c>{udid}.plist</c>) that does not carry a
/// <c>WiFiMACAddress</c> key must be SKIPPED rather than throwing
/// <see cref="System.Collections.Generic.KeyNotFoundException"/>. Previously the method indexed the
/// dictionary (<c>record["WiFiMACAddress"]</c>), which crashed every WiFi poll for any malformed/keyless
/// record and made WiFi-transport devices fail to resolve. The fix uses <c>TryGetValue</c> and drops
/// only the keyless record.
/// <para>
/// These tests run against a temp pair-records directory and exercise the file-parsing prologue, which
/// completes before the (time-bounded, device-free on CI) Bonjour browse. The assertion is simply that
/// enumeration does not throw — a keyless record no longer aborts the sweep.
/// </para>
/// </summary>
[TestClass]
public class GetMobdev2LockdownsTests
{
    private static string WriteRecord(string dir, string udid, bool withWiFiMac)
    {
        DictionaryNode record = new() {
            { "HostID", new StringNode("00000000-0000-0000-0000-000000000000") },
            { "SystemBUID", new StringNode("11111111-1111-1111-1111-111111111111") },
        };
        if (withWiFiMac) {
            record.Add("WiFiMACAddress", new StringNode("aa:bb:cc:dd:ee:ff"));
        }

        string path = Path.Combine(dir, $"{udid}.plist");
        File.WriteAllBytes(path, PropertyList.SaveAsByteArray(record, PlistFormat.Xml));
        return path;
    }

    private static async Task DrainAsync(string pairRecordsPath, ILogger? logger = null)
    {
        // A short Bonjour timeout keeps the test fast; on a device-free CI host the browse yields no
        // matches, so the enumerator simply completes after parsing the on-disk records.
        await foreach ((string _, TcpLockdownClient lockdown) in
            LockdownService.GetMobdev2Lockdowns(pairRecordsPath: pairRecordsPath, timeout: 1, logger: logger)) {
            lockdown.Close();
        }
    }

    /// <summary>
    /// Captures every formatted log message so a test can assert that per-sweep diagnostics were
    /// emitted (ScribeHold #1905 — a zero-result sweep must no longer be silent).
    /// </summary>
    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));
    }

    [TestMethod]
    public async Task PairRecordMissingWiFiMACAddress_IsSkipped_DoesNotThrow()
    {
        string dir = Directory.CreateTempSubdirectory("nimd-1901-").FullName;
        try {
            // One record WITHOUT the key — the old indexer access threw KeyNotFoundException here.
            WriteRecord(dir, "00008110-AAAA1111BBBB2222", withWiFiMac: false);

            await DrainAsync(dir);
            // Reaching here without an exception is the assertion: the keyless record was skipped.
        }
        finally {
            Directory.Delete(dir, recursive: true);
        }
    }

    [TestMethod]
    public async Task MixedRecords_KeylessSkipped_ValidStillParsed_DoesNotThrow()
    {
        string dir = Directory.CreateTempSubdirectory("nimd-1901-").FullName;
        try {
            // A valid record and a keyless one in the same directory: the valid one is registered for
            // matching, the keyless one is dropped — neither path throws.
            WriteRecord(dir, "00008110-CCCC3333DDDD4444", withWiFiMac: true);
            WriteRecord(dir, "00008110-EEEE5555FFFF6666", withWiFiMac: false);

            await DrainAsync(dir);
        }
        finally {
            Directory.Delete(dir, recursive: true);
        }
    }

    [TestMethod]
    public async Task Sweep_EmitsPerSweepDiagnostics_DistinguishingLoadedFromSkipped()
    {
        string dir = Directory.CreateTempSubdirectory("nimd-1905-").FullName;
        CapturingLogger logger = new();
        try {
            // One matchable record + one keyless record: the summary must report both counts so a
            // reader can tell "Apple-written record carries no WiFi MAC" from "nothing advertising".
            WriteRecord(dir, "00008110-AAAA1111BBBB2222", withWiFiMac: true);
            WriteRecord(dir, "00008110-CCCC3333DDDD4444", withWiFiMac: false);

            await DrainAsync(dir, logger);

            // The sweep-start summary reports matchable + skipped record counts and the advertisement
            // count, so a 0-device sweep is no longer silent.
            bool hasSweepSummary = logger.Messages.Exists(m =>
                m.Contains("mobdev2 sweep:") &&
                m.Contains("1 matchable") &&
                m.Contains("1 skipped"));
            Assert.IsTrue(hasSweepSummary, "Expected a per-sweep summary line with matchable/skipped record counts. Messages: " + string.Join(" | ", logger.Messages));

            // The outcome summary reports matched/unmatched/seen so "0 advertising" vs "all skipped"
            // is distinguishable.
            bool hasResultSummary = logger.Messages.Exists(m => m.Contains("mobdev2 sweep result:"));
            Assert.IsTrue(hasResultSummary, "Expected a per-sweep result summary line. Messages: " + string.Join(" | ", logger.Messages));
        }
        finally {
            Directory.Delete(dir, recursive: true);
        }
    }
}
