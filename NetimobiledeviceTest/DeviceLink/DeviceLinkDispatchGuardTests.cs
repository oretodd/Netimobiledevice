using Netimobiledevice.DeviceLink;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork regression tests for the DlLoop dispatch guard (#2199 P2-3).
///
/// Background: an unknown/new DeviceLink command used to fall into the default switch arm — which
/// dereferenced <c>message[3]</c> unguarded and then indexed <c>DeviceLinkHandlers[command]</c>
/// (KeyNotFoundException) — killing the whole backup to a generic fatal. The fix resolves the handler
/// with <c>TryGetValue</c> and replies with an unsupported-operation status + continues.
///
/// The subtle trap the guard MUST get right: <c>DLMessageProcessMessage</c> is the terminal completion
/// message iOS sends to end a backup, and it is DELIBERATELY absent from the <c>DeviceLinkHandlers</c>
/// dictionary — it is handled entirely by the DlLoop switch (which returns Success). If the guard
/// classified "no handler" as "unsupported" naively, EVERY backup's completion would be misclassified
/// and the loop would never return Success. These tests pin the pure decision
/// (<see cref="DeviceLinkService.IsUnsupportedDeviceLinkCommand"/>) so that regression can never return.
/// </summary>
[TestClass]
public class DeviceLinkDispatchGuardTests
{
    [TestMethod]
    [Description("#2199 P2-3: a command with no handler that is NOT ProcessMessage is unsupported (reply + continue).")]
    public void UnknownCommand_NoHandler_IsUnsupported()
    {
        Assert.IsTrue(
            DeviceLinkService.IsUnsupportedDeviceLinkCommand("DLMessageSomeFutureIosThing", hasHandler: false),
            "A new/unknown command with no handler must be treated as unsupported so the backup replies with an error status and continues instead of dying.");
    }

    [TestMethod]
    [Description("#2199 P2-3: ProcessMessage — the switch-only terminal completion command — must NEVER be classified as unsupported, even though it has no handler entry.")]
    public void ProcessMessage_NoHandler_IsNotUnsupported()
    {
        Assert.IsFalse(
            DeviceLinkService.IsUnsupportedDeviceLinkCommand("DLMessageProcessMessage", hasHandler: false),
            "ProcessMessage is handled entirely by the DlLoop switch (returns Success). It is deliberately absent from DeviceLinkHandlers and must be treated as KNOWN — misclassifying it would make every backup fail to complete.");
    }

    [TestMethod]
    [Description("#2199 P2-3: a known command WITH a handler is never unsupported.")]
    public void KnownCommand_WithHandler_IsNotUnsupported()
    {
        Assert.IsFalse(
            DeviceLinkService.IsUnsupportedDeviceLinkCommand("DLMessageDownloadFiles", hasHandler: true),
            "A command with a DeviceLinkHandlers entry is supported and must be dispatched, not shunted to the unsupported path.");
    }

    [TestMethod]
    [Description("#2199 P2-3: the ProcessMessage exception is keyed off the canonical DeviceLinkMessage constant, not a stray literal.")]
    public void ProcessMessageConstant_MatchesTheGuardException()
    {
        // If DeviceLinkMessage.ProcessMessage ever drifts, this test drifts with it — proving the guard
        // exception tracks the real constant rather than a hardcoded string.
        Assert.IsFalse(
            DeviceLinkService.IsUnsupportedDeviceLinkCommand(DeviceLinkMessage.ProcessMessage, hasHandler: false),
            "The guard must exempt exactly the DeviceLinkMessage.ProcessMessage constant.");
    }
}
