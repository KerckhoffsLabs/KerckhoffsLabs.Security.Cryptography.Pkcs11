using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// <c>SupportsMechanism</c> issues C_GetSessionInfo and C_GetMechanismList and lazily publishes the
/// result, so it owes the same single-thread contract as every other native-touching method on the
/// session. These tests pin that it takes the busy lock for its whole body — the cached read
/// included, since an unsynchronized read of the cache reference is the unsafe publication half of
/// the same race.
/// </summary>
public sealed class Pkcs11SessionSupportsMechanismRaceTests
{
    private const ulong SessionId = 43;

    /// <summary>Upper bound for a wait that is only ever reached when something has gone wrong.</summary>
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Parks inside <c>C_GenerateRandom</c> until released, and records whether either of the
    /// mechanism-probe calls was entered while that call was still on the stack.
    /// </summary>
    private sealed class ParkingMechListFake : FakeLowLevelPkcs11Library
    {
        internal readonly ManualResetEventSlim Entered = new(false);
        internal readonly ManualResetEventSlim Release = new(false);

        private volatile bool _inFlight;

        /// <summary>Set if a probe call was issued while a native call was still executing.</summary>
        internal volatile bool ProbedDuringNativeCall;

        internal CKM[] Mechanisms = [CKM.CKM_AES_GCM, CKM.CKM_SHA256];

        public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
        {
            _inFlight = true;
            Entered.Set();
            Release.Wait(Generous);
            _inFlight = false;
            return CKR.CKR_OK;
        }

        public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        {
            if (_inFlight)
                ProbedDuringNativeCall = true;
            info.SlotId = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        public override CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
        {
            if (_inFlight)
                ProbedDuringNativeCall = true;

            if (mechanismList is null)
            {
                count = (NativeCULong)Mechanisms.Length;
                return CKR.CKR_OK;
            }

            for (int i = 0; i < Mechanisms.Length; i++)
                mechanismList[i] = Mechanisms[i];
            count = (NativeCULong)Mechanisms.Length;
            return CKR.CKR_OK;
        }

        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
    }

    private sealed record ProbeOutcome(bool ProbedDuringNativeCall, Exception? ProbeFailure);

    /// <summary>
    /// Parks a worker thread inside a native call, probes for mechanism support from a second
    /// thread while it is parked, then lets the worker finish and reports what happened.
    /// </summary>
    /// <param name="warmTheCacheFirst">
    /// When true the probe runs against an already-populated cache, which is the path that skips
    /// the native calls entirely and so is only covered by the lock if the lock spans the whole method.
    /// </param>
    private static ProbeOutcome ProbeWhileACallIsInFlight(bool warmTheCacheFirst)
    {
        var fake = new ParkingMechListFake();
        var session = new Pkcs11Session(fake, SessionId);

        if (warmTheCacheFirst)
            Assert.True(session.SupportsMechanism(CKM.CKM_AES_GCM));

        Exception? probeFailure = null;

        var worker = new Thread(() => session.GenerateRandom(8)) { IsBackground = true };
        var prober = new Thread(() =>
        {
            try
            {
                session.SupportsMechanism(CKM.CKM_AES_GCM);
            }
            catch (Exception ex)
            {
                probeFailure = ex;
            }
        })
        { IsBackground = true };

        worker.Start();
        Assert.True(fake.Entered.Wait(Generous), "the worker never reached the native call");

        // The worker is now parked inside C_GenerateRandom holding the busy lock.
        prober.Start();
        Assert.True(prober.Join(Generous), "the probe never returned — it is waiting on a lock the worker holds");

        fake.Release.Set();
        Assert.True(worker.Join(Generous), "the worker thread did not finish");

        return new ProbeOutcome(fake.ProbedDuringNativeCall, probeFailure);
    }

    [Fact]
    public void SupportsMechanism_DoesNotProbeTheTokenWhileANativeCallIsInFlight()
    {
        ProbeOutcome outcome = ProbeWhileACallIsInFlight(warmTheCacheFirst: false);

        Assert.False(outcome.ProbedDuringNativeCall);
    }

    [Fact]
    public void SupportsMechanism_ReportsCrossThreadContention_TheSameWayEveryOtherOperationDoes()
    {
        ProbeOutcome outcome = ProbeWhileACallIsInFlight(warmTheCacheFirst: false);

        Assert.IsType<InvalidOperationException>(outcome.ProbeFailure);
        Assert.Contains("Concurrent access", outcome.ProbeFailure!.Message);
    }

    /// <summary>
    /// The cached read is guarded too. Reading the cache reference outside the lock is the unsafe
    /// publication half of this race, so a fix that brackets only the lazy population leaves the
    /// common path — every call after the first — unsynchronized.
    /// </summary>
    [Fact]
    public void SupportsMechanism_GuardsTheCachedReadToo_NotJustThePopulation()
    {
        ProbeOutcome outcome = ProbeWhileACallIsInFlight(warmTheCacheFirst: true);

        Assert.IsType<InvalidOperationException>(outcome.ProbeFailure);
    }

    /// <summary>
    /// Same-thread reentrancy still works: the probe is reachable from adapter code that may
    /// already hold the lock, and Monitor lets that through.
    /// </summary>
    [Fact]
    public void SupportsMechanism_FromInsideAnExclusiveSection_OnTheSameThread_Succeeds()
    {
        var fake = new ParkingMechListFake();
        var session = new Pkcs11Session(fake, SessionId);

        using var lease = session.AcquireExclusive(
            nameof(SupportsMechanism_FromInsideAnExclusiveSection_OnTheSameThread_Succeeds));

        Assert.True(session.SupportsMechanism(CKM.CKM_AES_GCM));
        Assert.False(session.SupportsMechanism(CKM.CKM_RSA_PKCS));
    }
}
