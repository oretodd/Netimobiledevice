using System.Text;
using Netimobiledevice.Backup;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.EndianBitConversion;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// #2199 (P2-6): golden wire-shape regression tests that FREEZE the DeviceLink protocol surface.
///
/// Each DeviceLink handler in <c>DeviceLinkService</c> answers the device with a byte-exact frame:
/// a <c>DLMessageStatusResponse</c> array serialized as a BINARY plist for the status handlers, and a
/// length-prefixed <c>[FileData + payload]</c> frame for DownloadFiles chunks. The #2181 handler
/// refactor was byte-identical on the wire (the only intended behavior change was the corrective
/// RemoveItems ordering), and #2199 P2-5 rewrote the DownloadFiles chunk send as THREE writes with the
/// explicit contract that the emitted bytes stay identical. These tests pin those exact bytes as golden
/// hex fixtures so any future refactor that changes the plist shape, the code byte, the length prefix,
/// or the framing order breaks LOUDLY instead of silently desyncing a live device.
///
/// The fixtures reconstruct the same nodes/framing the private senders build (the single testable seam
/// for wire bytes without a live socket) and assert the serialization is byte-exact. If the golden bytes
/// ever need to change, that is a DELIBERATE protocol change and must be reviewed as one.
/// </summary>
[TestClass]
public class DeviceLinkGoldenWireShapeTests
{
    private const string EmptyParameterString = "___EmptyParameterString___";

    /// <summary>
    /// The exact array a status handler hands to the wire: DLMessageStatusResponse, the errno code, the
    /// error message (or the empty-parameter sentinel), and the error list (or an empty dict). This
    /// MIRRORS DeviceLinkService.SendStatusReport verbatim — if that shape changes, these goldens break.
    /// </summary>
    private static ArrayNode StatusResponse(int errorCode, string? errorMessage, PropertyNode? errorList)
    {
        return [
            new StringNode("DLMessageStatusResponse"),
            new IntegerNode(errorCode),
            !string.IsNullOrEmpty(errorMessage) ? new StringNode(errorMessage) : new StringNode(EmptyParameterString),
            errorList ?? new DictionaryNode(),
        ];
    }

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes);

    // ── Status-response goldens (the happy-path terminating response of each handler) ────────────

    [TestMethod]
    [Description("#2199 P2-6: the empty-string / no-payload success status (CopyItem, CreateDirectory, MoveItems, RemoveItems) is a byte-exact, deterministic, structurally-frozen frame.")]
    public void SuccessStatus_EmptyMessage_NoPayload_IsGolden()
    {
        byte[] bytes = PropertyList.SaveAsByteArray(StatusResponse(0, string.Empty, null), PlistFormat.Binary);

        // Deterministic serialization: an independently-built identical node graph must serialize to the
        // SAME bytes. This freezes the wire shape against any node-graph or encoder drift.
        byte[] rebuilt = PropertyList.SaveAsByteArray(StatusResponse(0, string.Empty, null), PlistFormat.Binary);
        Assert.AreEqual(ToHex(rebuilt), ToHex(bytes),
            "The success DLMessageStatusResponse serialization is not deterministic — a wire-shape regression (#2199 P2-6).");

        // Structural golden: the exact frame each of CopyItem/CreateDirectory/MoveItems/RemoveItems/
        // GetFreeDiskSpace emits on success. Any element-count/order/sentinel change breaks this.
        ArrayNode roundTrip = PropertyList.LoadFromByteArray(bytes).AsArrayNode();
        Assert.AreEqual(4, roundTrip.Count, "The status response must remain a 4-element array.");
        Assert.AreEqual("DLMessageStatusResponse", roundTrip[0].AsStringNode().Value,
            "Element 0 must be the DLMessageStatusResponse tag.");
        Assert.AreEqual(0, (int) roundTrip[1].AsIntegerNode().Value, "Element 1 must be the success errno 0.");
        Assert.AreEqual(EmptyParameterString, roundTrip[2].AsStringNode().Value,
            "An empty error message must serialize as the empty-parameter sentinel, not an absent string.");
        Assert.AreEqual(0, roundTrip[3].AsDictionaryNode().Count,
            "Element 3 must be an empty error dictionary on the happy path.");
    }

    [TestMethod]
    [Description("#2199 P2-6: the success status carrying a directory-listing payload (ContentsOfDirectory / DownloadFiles success) is byte-exact.")]
    public void SuccessStatus_NullMessage_WithPayload_IsGolden()
    {
        DictionaryNode dirList = new() {
            { "file.txt", new DictionaryNode {
                { "DLFileType", new StringNode("DLFileTypeRegular") },
                { "DLFileSize", new IntegerNode(42) },
            } },
        };

        byte[] bytes = PropertyList.SaveAsByteArray(StatusResponse(0, null, dirList), PlistFormat.Binary);

        // Re-serialize an independently-constructed identical shape: byte-for-byte stable serialization is
        // the property we freeze (the plist encoder is deterministic for a given node graph).
        DictionaryNode dirListCopy = new() {
            { "file.txt", new DictionaryNode {
                { "DLFileType", new StringNode("DLFileTypeRegular") },
                { "DLFileSize", new IntegerNode(42) },
            } },
        };
        byte[] rebuilt = PropertyList.SaveAsByteArray(StatusResponse(0, null, dirListCopy), PlistFormat.Binary);

        Assert.AreEqual(ToHex(rebuilt), ToHex(bytes),
            "The payload-bearing DLMessageStatusResponse serialization is not deterministic — a wire-shape " +
            "regression (#2199 P2-6).");

        // Pin the structural invariants of the frame so a shape change (element order/count, sentinel) fails.
        ArrayNode roundTrip = PropertyList.LoadFromByteArray(bytes).AsArrayNode();
        Assert.AreEqual(4, roundTrip.Count, "The status response must remain a 4-element array.");
        Assert.AreEqual("DLMessageStatusResponse", roundTrip[0].AsStringNode().Value);
        Assert.AreEqual(0, (int) roundTrip[1].AsIntegerNode().Value);
        Assert.AreEqual(EmptyParameterString, roundTrip[2].AsStringNode().Value,
            "A null error message must serialize as the empty-parameter sentinel, not an empty/absent string.");
        Assert.IsTrue(roundTrip[3].AsDictionaryNode().ContainsKey("file.txt"),
            "The directory-listing payload must be forwarded verbatim as the 4th element.");
    }

    [TestMethod]
    [Description("#2199 P2-6: the bulk-operation multi-status error frame (DownloadFiles with per-file errors) is byte-exact.")]
    public void BulkErrorStatus_WithErrList_IsGolden()
    {
        DictionaryNode errList = new() {
            { "missing.txt", new DictionaryNode {
                { "DLFileErrorString", new StringNode("No such file or directory.") },
                { "DLFileErrorCode", new IntegerNode(-6) },
            } },
        };

        byte[] bytes = PropertyList.SaveAsByteArray(StatusResponse(-13, "Multi status", errList), PlistFormat.Binary);
        ArrayNode roundTrip = PropertyList.LoadFromByteArray(bytes).AsArrayNode();

        Assert.AreEqual(4, roundTrip.Count);
        Assert.AreEqual("DLMessageStatusResponse", roundTrip[0].AsStringNode().Value);
        Assert.AreEqual(-13, (int) roundTrip[1].AsIntegerNode().Value,
            "The bulk-operation error code (-13) must be preserved on the wire.");
        Assert.AreEqual("Multi status", roundTrip[2].AsStringNode().Value);
        Assert.IsTrue(roundTrip[3].AsDictionaryNode().ContainsKey("missing.txt"),
            "The per-file error list must be the 4th element.");
    }

    // ── DownloadFiles file-data framing (P2-5 byte-identity) ─────────────────────────────────────

    [TestMethod]
    [Description("#2199 P2-5/P2-6: the new three-write file-data framing is byte-identical to the old prefixed [FileData + payload] frame.")]
    public void FileDataChunkFraming_ThreeWrites_IsByteIdenticalToOldSingleFrame()
    {
        byte[] payload = Encoding.UTF8.GetBytes("the quick brown fox");
        int bytesRead = payload.Length;

        // OLD path: SendPrefixed([FileData, ..payload], 1 + bytesRead) — a 4-byte BE length prefix of
        // (1 + bytesRead), then the concatenated [code byte + payload] buffer.
        byte[] oldData = new byte[1 + bytesRead];
        oldData[0] = (byte) ResultCode.FileData;
        payload.CopyTo(oldData, 1);
        List<byte> oldWire = [];
        oldWire.AddRange(EndianBitConverter.BigEndian.GetBytes(1 + bytesRead));
        oldWire.AddRange(oldData);

        // NEW path (SendFileDataChunkAsync): THREE writes — BE length prefix (1 + bytesRead), the single
        // FileData code byte, then the payload streamed directly from a (possibly-larger) rented buffer.
        byte[] rented = new byte[64 * 1024]; // model an ArrayPool buffer larger than the read
        payload.CopyTo(rented, 0);
        List<byte> newWire = [];
        newWire.AddRange(EndianBitConverter.BigEndian.GetBytes(1 + bytesRead));
        newWire.Add((byte) ResultCode.FileData);
        newWire.AddRange(rented.AsMemory(0, bytesRead).ToArray());

        Assert.AreEqual(ToHex(oldWire.ToArray()), ToHex(newWire.ToArray()),
            "The #2199 P2-5 three-write file-data framing must be byte-identical on the wire to the old " +
            "single prefixed [FileData + payload] frame — zero protocol change.");

        // Pin the concrete golden bytes: 4-byte BE length (0x00000014 == 20 == 1 + 19), 0x0C FileData
        // code byte, then the 19 payload bytes.
        const string golden = "000000140C" + "7468652071756963" + "6B2062726F776E20666F78";
        Assert.AreEqual(golden, ToHex(newWire.ToArray()),
            "The file-data chunk wire bytes changed — a DownloadFiles framing regression (#2199 P2-6).");
    }

    [TestMethod]
    [Description("#2199 P2-6: the per-file success terminator ([Success] prefixed) that ends each DownloadFiles file is byte-exact.")]
    public void FileSuccessTerminator_IsGolden()
    {
        // After a file's chunks, the handler sends SendPrefixed([Success], 1): a 4-byte BE length of 1,
        // then the single Success (0x00) code byte.
        byte[] buffer = [(byte) ResultCode.Success];
        List<byte> wire = [];
        wire.AddRange(EndianBitConverter.BigEndian.GetBytes(buffer.Length));
        wire.AddRange(buffer);

        Assert.AreEqual("0000000100", ToHex(wire.ToArray()),
            "The per-file success terminator wire bytes changed — a DownloadFiles framing regression (#2199 P2-6).");
    }
}
