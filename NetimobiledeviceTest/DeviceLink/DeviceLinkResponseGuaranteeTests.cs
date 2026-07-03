using System.Collections.Concurrent;
using Netimobiledevice.DeviceLink;
using Netimobiledevice.Plist;

namespace NetimobiledeviceTest.DeviceLink;

/// <summary>
/// Fork tests for the DeviceLink handler cancellation-safety guarantee (#2181).
///
/// Background: the silent <c>Backup_Preparing</c> wedge is caused by DeviceLink handlers
/// (<c>ContentsOfDirectory</c>, <c>MoveItems</c>, <c>RemoveItems</c>, <c>GetFreeDiskSpace</c>, ...)
/// sending their required terminating <c>DLMessageStatusResponse</c> only inside
/// <c>if (!cancellationToken.IsCancellationRequested)</c> and <c>break</c>-ing out of their loops on
/// cancellation. When the token trips mid-handler the handler returned WITHOUT responding — the device
/// blocks forever waiting for the response and <c>DlLoop</c> blocks forever waiting for the device
/// (mutual deadlock).
///
/// The fix routes every handler's terminating response through <see cref="DeviceLinkResponseGuarantee"/>,
/// which sends EXACTLY ONE terminating response even when the handler is cancelled mid-body — the
/// response is discharged on <see cref="CancellationToken.None"/> in <c>DisposeAsync</c> before the
/// cancellation propagates. These tests pin that guarantee (the single testable place the
/// exactly-one-response semantics live) without a live socket, by driving it with a capturing fake
/// sender that models the handler-usage shape.
/// </summary>
[TestClass]
public class DeviceLinkResponseGuaranteeTests
{
    private sealed record SentStatus(int ErrorCode, string? ErrorMessage, PropertyNode? Payload, bool TokenWasCancelled);

    /// <summary>
    /// A capturing <see cref="DeviceLinkStatusSender"/> that records every terminating status send
    /// (and whether the token it was handed was already cancelled), so a test can assert the exact
    /// count and the fact that the guaranteed send happened on an uncancelled token.
    /// </summary>
    private sealed class CapturingSender
    {
        private readonly ConcurrentQueue<SentStatus> _sent = new();

        public IReadOnlyList<SentStatus> Sent => _sent.ToArray();

        public DeviceLinkStatusSender Delegate => (errorCode, errorMessage, payload, ct) => {
            _sent.Enqueue(new SentStatus(errorCode, errorMessage, payload, ct.IsCancellationRequested));
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Models the FIXED handler shape: honor cancellation for the loop body, send the terminating
    /// status through the guarantee. Mirrors e.g. MoveItems/ContentsOfDirectory/RemoveItems in
    /// DeviceLinkService.
    /// </summary>
    private static async Task RunGuardedHandler(DeviceLinkResponseGuarantees guarantees, int itemCount, CancellationToken cancellationToken)
    {
        await using IDeviceLinkResponseGuarantee guard = guarantees.Create();
        for (int i = 0; i < itemCount; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            // (real handler does file work here)
        }
        await guard.SendTerminatingStatusAsync(0, null, null, cancellationToken).ConfigureAwait(false);
    }

    // ── (a) The core prevention assertion ──────────────────────────────────────────────────────

    [TestMethod]
    [Description("A handler cancelled MID-execution still writes exactly one terminating response, then propagates the cancellation.")]
    public async Task CancelledMidHandler_SendsExactlyOneTerminatingResponse_ThenPropagates()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        // A token already cancelled before the loop body runs — the strongest form of "mid-handler
        // cancellation": ThrowIfCancellationRequested fires before the explicit send is reached.
        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            () => RunGuardedHandler(guarantees, itemCount: 5, cts.Token),
            "The handler must propagate the cancellation after discharging its response.");

        Assert.AreEqual(1, sender.Sent.Count,
            "Exactly ONE terminating DLMessageStatusResponse must be sent even when the handler is cancelled mid-body (the device is never left blocking).");
        Assert.IsFalse(sender.Sent[0].TokenWasCancelled,
            "The guaranteed response must be sent on CancellationToken.None so it goes out even though the handler's own token was cancelled.");
    }

    [TestMethod]
    [Description("Cancellation partway through a multi-item loop still yields exactly one terminating response.")]
    public async Task CancelledPartwayThroughLoop_SendsExactlyOneResponse()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        using CancellationTokenSource cts = new();

        // Cancel after the guarantee is created but during the loop body: model by cancelling on the
        // 3rd iteration via a custom handler that flips the token mid-loop.
        async Task Handler()
        {
            await using IDeviceLinkResponseGuarantee guard = guarantees.Create();
            for (int i = 0; i < 10; i++) {
                if (i == 3) {
                    cts.Cancel();
                }
                cts.Token.ThrowIfCancellationRequested();
            }
            await guard.SendTerminatingStatusAsync(0, null, null, cts.Token).ConfigureAwait(false);
        }

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(Handler,
            "Cancellation mid-loop must still propagate after the response is discharged.");

        Assert.AreEqual(1, sender.Sent.Count,
            "A mid-loop cancellation must still discharge exactly one terminating response.");
        Assert.IsFalse(sender.Sent[0].TokenWasCancelled,
            "The discharge happens on CancellationToken.None.");
    }

    // ── Exactly-once / normal-path semantics ───────────────────────────────────────────────────

    [TestMethod]
    [Description("The normal (uncancelled) path sends exactly one terminating response and dispose does not double-send.")]
    public async Task NormalPath_SendsExactlyOnce_DisposeIsNoOp()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        await RunGuardedHandler(guarantees, itemCount: 3, CancellationToken.None);

        Assert.AreEqual(1, sender.Sent.Count,
            "A handler that sends its response explicitly must not have dispose send a second one.");
        Assert.AreEqual(0, sender.Sent[0].ErrorCode);
    }

    [TestMethod]
    [Description("An explicit send followed by a second call is a no-op (send-exactly-once latch).")]
    public async Task SecondExplicitSend_IsNoOp()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        await using IDeviceLinkResponseGuarantee guard = guarantees.Create();
        await guard.SendTerminatingStatusAsync(0, "first", null, CancellationToken.None);
        await guard.SendTerminatingStatusAsync(13, "second", null, CancellationToken.None);

        Assert.IsTrue(guard.Responded, "Responded must latch true after the first send.");
        Assert.AreEqual(1, sender.Sent.Count, "The second SendTerminatingStatusAsync must be a no-op.");
        Assert.AreEqual("first", sender.Sent[0].ErrorMessage, "The FIRST send wins; the second is dropped.");
    }

    [TestMethod]
    [Description("A handler that returns WITHOUT sending (early return) still has exactly one response discharged at dispose.")]
    public async Task HandlerReturnsWithoutSending_DisposeDischargesDefaultResponse()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        // Simulate a buggy/early-return handler that never calls SendTerminatingStatusAsync.
        await using (IDeviceLinkResponseGuarantee guard = guarantees.Create()) {
            Assert.IsFalse(guard.Responded, "Precondition: nothing sent yet.");
        }

        Assert.AreEqual(1, sender.Sent.Count,
            "DisposeAsync must discharge a default terminating response so no handler path returns owing a response.");
        Assert.AreEqual(0, sender.Sent[0].ErrorCode, "The default discharge is a success (0) status.");
        Assert.IsFalse(sender.Sent[0].TokenWasCancelled, "The default discharge is on CancellationToken.None.");
    }

    [TestMethod]
    [Description("The payload passed to SendTerminatingStatusAsync reaches the sender unchanged (e.g. a directory listing).")]
    public async Task Payload_IsForwardedToSender()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        DictionaryNode payload = new() { { "entry", new StringNode("value") } };
        await using (IDeviceLinkResponseGuarantee guard = guarantees.Create()) {
            await guard.SendTerminatingStatusAsync(0, null, payload, CancellationToken.None);
        }

        Assert.AreEqual(1, sender.Sent.Count);
        Assert.AreSame(payload, sender.Sent[0].Payload, "The payload node must be forwarded to the sender verbatim.");
    }

    [TestMethod]
    [Description("If the explicit send THROWS (socket gone), dispose still discharges the response on CancellationToken.None.")]
    public async Task ExplicitSendThrows_DisposeStillDischarges()
    {
        int callCount = 0;
        // First send throws (socket dropped mid-response); the dispose fallback then succeeds.
        DeviceLinkStatusSender flaky = (errorCode, errorMessage, payload, ct) => {
            callCount++;
            if (callCount == 1) {
                throw new IOException("socket gone");
            }
            return Task.CompletedTask;
        };
        DeviceLinkResponseGuarantees guarantees = new(flaky);

        await using (IDeviceLinkResponseGuarantee guard = guarantees.Create()) {
            await Assert.ThrowsExactlyAsync<IOException>(
                () => guard.SendTerminatingStatusAsync(0, null, null, CancellationToken.None),
                "The first send throws through to the handler (the failure is observable).");
            Assert.IsFalse(guard.Responded, "A FAILED send must not latch Responded — the obligation is still outstanding.");
        }

        Assert.AreEqual(2, callCount,
            "A failed explicit send must not latch; dispose retries the discharge so the response is still guaranteed.");
    }

    // ── #2189: the dispose-fallback send is time-bounded so a wedged socket cannot hang teardown ──

    [TestMethod]
    [Description("#2189: a dispose-fallback send that hangs on a wedged socket is abandoned within the ~5s bound — DisposeAsync completes, it does not block forever.")]
    public async Task DisposeFallbackSend_OnWedgedSocket_IsBoundedAndCompletes()
    {
        // Model the wedged socket: the sender blocks until ITS token is cancelled (the underlying
        // WriteAsync ignores WriteTimeout, so without the #2189 bound this would never return and
        // DisposeAsync — and the whole `await using` — would hang indefinitely).
        DeviceLinkStatusSender wedged = async (errorCode, errorMessage, payload, ct) => {
            var tcs = new TaskCompletionSource();
            using (ct.Register(() => tcs.TrySetResult())) {
                await tcs.Task.ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
        };
        DeviceLinkResponseGuarantees guarantees = new(wedged);

        // A handler that returns without responding, so DisposeAsync runs the fallback send. The whole
        // dispose must complete well within a window that proves it is bounded (the bound is ~5s; give a
        // generous ceiling so a slow CI box does not flake while still failing an unbounded hang).
        async Task DisposeGuard()
        {
            await using IDeviceLinkResponseGuarantee guard = guarantees.Create();
            // no explicit send — dispose discharges the (wedged) fallback
        }

        Task dispose = DisposeGuard();
        Task completed = await Task.WhenAny(dispose, Task.Delay(TimeSpan.FromSeconds(30)));

        Assert.AreSame(dispose, completed,
            "DisposeAsync must return once the ~5s fallback bound elapses on a wedged socket — never hang teardown.");
        await dispose; // must not throw: the dispose fallback swallows the timeout (best-effort discharge).
    }

    [TestMethod]
    [Description("#2189: the dispose-fallback token is time-bounded but NOT pre-cancelled — on a responsive socket the response still goes out.")]
    public async Task DisposeFallbackSend_OnResponsiveSocket_StillDischarges()
    {
        CapturingSender sender = new();
        DeviceLinkResponseGuarantees guarantees = new(sender.Delegate);

        await using (IDeviceLinkResponseGuarantee guard = guarantees.Create()) {
            // no explicit send — dispose discharges the fallback on the bounded token
        }

        Assert.AreEqual(1, sender.Sent.Count,
            "The bounded dispose fallback must still discharge exactly one terminating response on a responsive socket.");
        Assert.IsFalse(sender.Sent[0].TokenWasCancelled,
            "The ~5s bound must not pre-cancel the token — a healthy send completes long before the deadline.");
    }
}
