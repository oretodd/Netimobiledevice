using Netimobiledevice.Lockdown.Pairing;
using Netimobiledevice.Plist;
using System.IO;

namespace NetimobiledeviceTest.Lockdown.Pairing;

[TestClass]
public class PairRecordsNoMuxTests
{
    // Observed on a Wi-Fi-only host with no usbmuxd running: every TCP lockdown open failed with
    // "Can't create and/or connect to Usbmux socket" although the pair record was on disk.
    [TestMethod]
    public void GetPreferredPairRecord_NoMuxListening_FallsBackToTheLocalRecord()
    {
        DirectoryInfo dir = Directory.CreateTempSubdirectory("pairrecords-");
        try {
            const string udid = "NO-MUX-TEST-UDID";
            var record = new DictionaryNode { { "HostID", new StringNode("host-1") } };
            File.WriteAllBytes(Path.Combine(dir.FullName, $"{udid}.plist"), PropertyList.SaveAsByteArray(record, PlistFormat.Xml));

            DictionaryNode found = PairRecords.GetPreferredPairRecord(udid, dir, usbmuxAddress: "127.0.0.1:1");

            Assert.AreEqual("host-1", found["HostID"].AsStringNode().Value);
        }
        finally {
            dir.Delete(recursive: true);
        }
    }
}
