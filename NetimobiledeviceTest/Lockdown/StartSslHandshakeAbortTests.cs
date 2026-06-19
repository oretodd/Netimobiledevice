using System.Net.Sockets;
using System.Security.Authentication;
using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Tests for the e1 portion of ScribeHold #1958: <see cref="ServiceConnection.StartSsl"/> must treat a
/// device-side TLS-handshake abort as a recoverable handshake FAILURE (return <c>false</c>) rather than
/// letting the exception propagate and abort the whole lockdown connect.
/// <para>
/// The root cause: an already-paired device DECLINES the autopair SSL re-validation of the lockdown
/// CONTROL connect, tearing the socket down mid-handshake. <c>AuthenticateAsClientAsync</c> surfaces this
/// as a <see cref="SocketException"/> with <see cref="SocketError.ConnectionAborted"/> (WSAECONNABORTED,
/// 10053) — sometimes wrapped in an <see cref="IOException"/>. The Wave-1 bisect reproduced it with the
/// host VPN OFF and re-trust OFF, ruling out a VPN/firewall artifact and stale escrow. Before the fix
/// this 10053 propagated through <c>ValidatePairing</c> → <c>HandleAutoPair</c> → connect, leaving the
/// device "Unknown / disappeared"; after the fix the classifier folds it into the existing
/// handshake-failure path so an identity-readable (non-SSL) client survives.
/// </para>
/// <para>
/// These tests exercise the deterministic classifier <see cref="ServiceConnection.IsHandshakeConnectionAbort"/>
/// directly (a full <c>StartSsl</c> needs a live TLS peer, which is not available on CI). The classifier
/// is the load-bearing decision: it MUST recognise abort/reset (direct or wrapped) and MUST NOT swallow
/// unrelated failures (auth failures, other socket errors, generic exceptions), which keep their own
/// handling.
/// </para>
/// </summary>
[TestClass]
public class StartSslHandshakeAbortTests
{
    [TestMethod]
    public void ConnectionAborted_DirectSocketException_IsClassifiedAsAbort()
    {
        var ex = new SocketException((int)SocketError.ConnectionAborted);
        Assert.IsTrue(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }

    [TestMethod]
    public void ConnectionReset_DirectSocketException_IsClassifiedAsAbort()
    {
        var ex = new SocketException((int)SocketError.ConnectionReset);
        Assert.IsTrue(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }

    [TestMethod]
    public void ConnectionAborted_WrappedInIOException_IsClassifiedAsAbort()
    {
        // AuthenticateAsClientAsync commonly wraps the underlying socket abort in an IOException; the
        // classifier walks the inner-exception chain so the wrapped 10053 is still recognised.
        var ex = new IOException("The read operation failed", new SocketException((int)SocketError.ConnectionAborted));
        Assert.IsTrue(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }

    [TestMethod]
    public void ConnectionReset_DoublyWrapped_IsClassifiedAsAbort()
    {
        var ex = new AuthenticationException(
            "handshake failed",
            new IOException("inner", new SocketException((int)SocketError.ConnectionReset)));
        Assert.IsTrue(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }

    [TestMethod]
    public void UnrelatedSocketError_IsNotClassifiedAsAbort()
    {
        // A timeout / host-unreachable / refused socket error is NOT the device-declines-revalidation
        // signature and must keep its own handling (it is not folded into the abort path).
        var ex = new SocketException((int)SocketError.TimedOut);
        Assert.IsFalse(ServiceConnection.IsHandshakeConnectionAbort(ex));

        var refused = new SocketException((int)SocketError.ConnectionRefused);
        Assert.IsFalse(ServiceConnection.IsHandshakeConnectionAbort(refused));
    }

    [TestMethod]
    public void PureAuthenticationException_IsNotClassifiedAsAbort()
    {
        // An AuthenticationException with no socket-abort underneath is a genuine cert/auth failure and is
        // handled by the dedicated catch (AuthenticationException) arm, NOT by the abort classifier.
        var ex = new AuthenticationException("certificate rejected");
        Assert.IsFalse(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }

    [TestMethod]
    public void GenericException_WithNoSocketAbort_IsNotClassifiedAsAbort()
    {
        var ex = new InvalidOperationException("network stream is null");
        Assert.IsFalse(ServiceConnection.IsHandshakeConnectionAbort(ex));
    }
}
