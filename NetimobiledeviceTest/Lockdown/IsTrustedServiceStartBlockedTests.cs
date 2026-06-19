using Netimobiledevice.Lockdown;

namespace NetimobiledeviceTest.Lockdown;

/// <summary>
/// Tests for ScribeHold #1965: a device that ACCEPTED the <c>StartSession</c> handshake must remain
/// backup-capable (able to START a trusted lockdown service such as mobilebackup2) even when the lockdown
/// control-connect SSL re-validation was declined.
/// <para>
/// Background: #1958 seam e1 deliberately clears <see cref="LockdownClient.IsPaired"/> when the device
/// declines the control-connect SSL re-validation, so the device stays on the Connected list without a
/// "Unknown / Unknown Model" display (identity reads succeed over the non-SSL client). But the SAME
/// cleared <c>IsPaired</c> made <c>GetServiceConnectionAttributes</c> throw
/// <see cref="NotPairedException"/> on every backup — trading a display bug for a total backup failure.
/// </para>
/// <para>
/// The fix gates the trusted-service start on a SEPARATE "StartSession-validated" signal (with a present
/// pair record), not on the display-driven <c>IsPaired</c>. <c>StartSession</c> succeeding proves the
/// device recognises the pair record; mobilebackup2 negotiates its own SSL on the data socket, so there is
/// no reason a StartSession-validated device should be treated as not-paired for the backup path.
/// </para>
/// <para>
/// These tests exercise the deterministic decision
/// <see cref="LockdownClient.IsTrustedServiceStartBlocked"/> directly (a full
/// <c>GetServiceConnectionAttributes</c> needs a live device handshake, which is not available on CI). The
/// predicate is the load-bearing decision: it MUST keep the trusted path open for a StartSession-validated
/// device, MUST still block a genuinely unpaired device, and MUST never block an untrusted-connection
/// request.
/// </para>
/// </summary>
[TestClass]
public class IsTrustedServiceStartBlockedTests
{
    [TestMethod]
    public void StartSessionValidated_SslDeclined_TrustedService_IsNotBlocked()
    {
        // THE #1965 SCENARIO: StartSession accepted (pairRecordValidatedViaStartSession = true) with a
        // present pair record, but the control-connect SSL re-validation was declined so seam e1 cleared
        // IsPaired. mobilebackup2 (useTrustedConnection = true) MUST still be allowed to start.
        bool blocked = LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: true,
            isPaired: false,
            pairRecordValidatedViaStartSession: true,
            hasPairRecord: true);

        Assert.IsFalse(blocked, "A StartSession-validated device with a pair record must be backup-capable even when control-SSL was declined (#1965).");
    }

    [TestMethod]
    public void IsPaired_TrustedService_IsNotBlocked()
    {
        // The healthy path (the earlier 2x28 GB successes): the device ACCEPTED the SSL re-validation,
        // IsPaired = true. Trusted services start as before.
        bool blocked = LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: true,
            isPaired: true,
            pairRecordValidatedViaStartSession: true,
            hasPairRecord: true);

        Assert.IsFalse(blocked);
    }

    [TestMethod]
    public void NotPairedAndNotStartSessionValidated_TrustedService_IsBlocked()
    {
        // A genuinely unpaired device (StartSession was NOT accepted, IsPaired = false) MUST still be
        // blocked from a trusted-service start — the #1965 fix must not weaken the real not-paired guard.
        bool blocked = LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: true,
            isPaired: false,
            pairRecordValidatedViaStartSession: false,
            hasPairRecord: false);

        Assert.IsTrue(blocked);
    }

    [TestMethod]
    public void StartSessionValidated_ButNoPairRecord_TrustedService_IsBlocked()
    {
        // Defensive: the StartSession-validated signal only opens the trusted path WITH a present pair
        // record (the escrow bag is sourced from it). Without a pair record the trusted start stays blocked.
        bool blocked = LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: true,
            isPaired: false,
            pairRecordValidatedViaStartSession: true,
            hasPairRecord: false);

        Assert.IsTrue(blocked);
    }

    [TestMethod]
    public void UntrustedConnection_IsNeverBlocked()
    {
        // An untrusted-connection request (useTrustedConnection = false) is never gated by pairing state,
        // regardless of IsPaired / StartSession / pair-record state.
        Assert.IsFalse(LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: false, isPaired: false, pairRecordValidatedViaStartSession: false, hasPairRecord: false));

        Assert.IsFalse(LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: false, isPaired: false, pairRecordValidatedViaStartSession: true, hasPairRecord: true));

        Assert.IsFalse(LockdownClient.IsTrustedServiceStartBlocked(
            useTrustedConnection: false, isPaired: true, pairRecordValidatedViaStartSession: true, hasPairRecord: true));
    }
}
