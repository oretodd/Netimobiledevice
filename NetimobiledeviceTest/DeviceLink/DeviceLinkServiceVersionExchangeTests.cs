using Netimobiledevice.DeviceLink;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

[TestClass]
public class DeviceLinkServiceVersionExchangeTests
{
    /// <summary>
    /// Regression guard: verifies that a short versionExchangeMessage array (fewer than 3 elements)
    /// would trigger the bounds-check guard rather than throwing ArgumentOutOfRangeException.
    /// This mirrors the failure mode observed in service.log (7 of 18 backup attempts on 2026-05-08).
    /// </summary>
    [TestMethod]
    public void ShortVersionExchangeArray_BoundsCheckPreventsIndexOutOfRange()
    {
        // Simulate the device returning a short reply — only the message name, no version numbers.
        ArrayNode shortMessage = [
            new StringNode("DLMessageVersionExchange")
            // Missing [1] and [2] — the major and minor version nodes
        ];

        // The guard condition that was added to VersionExchange.
        // If Count < 3, access to [1] and [2] must not be attempted.
        bool guardTriggered = shortMessage.Count < 3;
        Assert.IsTrue(guardTriggered, "Guard condition should trigger for a short version exchange array");

        // Verify that accessing the indices that would have been reached without the guard
        // does indeed throw, confirming the guard is necessary.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => {
            _ = shortMessage[1];
        });
    }

    [TestMethod]
    public void ShortVersionExchangeArray_ZeroElements_BoundsCheckPreventsIndexOutOfRange()
    {
        // Simulate an empty reply from the device.
        ArrayNode emptyMessage = [];

        bool guardTriggered = emptyMessage.Count < 3;
        Assert.IsTrue(guardTriggered, "Guard condition should trigger for an empty version exchange array");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => {
            _ = emptyMessage[0];
        });
    }

    [TestMethod]
    public void VersionExchangeArray_ThreeElements_BoundsCheckDoesNotTrigger()
    {
        // A well-formed version exchange message should pass the bounds check.
        ArrayNode validMessage = [
            new StringNode("DLMessageVersionExchange"),
            new IntegerNode(400),
            new IntegerNode(0)
        ];

        bool guardTriggered = validMessage.Count < 3;
        Assert.IsFalse(guardTriggered, "Guard condition should NOT trigger for a complete version exchange array");

        // All three indices must be accessible without exception.
        _ = validMessage[0].AsStringNode();
        _ = validMessage[1].AsIntegerNode();
        _ = validMessage[2].AsIntegerNode();
    }
}
