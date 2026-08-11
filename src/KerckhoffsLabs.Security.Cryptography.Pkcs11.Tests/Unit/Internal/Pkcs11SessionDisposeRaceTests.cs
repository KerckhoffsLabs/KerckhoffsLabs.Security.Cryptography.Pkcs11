using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// <see cref="Pkcs11Session.Dispose()"/> releases the session handle, which issues
/// <c>C_CloseSession</c>. Session ids cross the P/Invoke boundary by value, so nothing at the
/// interop layer prevents that close from landing while another thread is still inside a native
/// call on the same session — only the busy lock every operation holds can. These tests pin both
/// halves of the contract: Dispose waits for an in-flight call, and it waits rather than throwing.
/// </summary>
public sealed class Pkcs11SessionDisposeRaceTests
{
    private const ulong SessionId = 42;

    /// <summary>Upper bound for a wait that is only ever reached when something has gone wrong.</summary>
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Parks inside <c>C_GenerateRandom</c> until released, and records whether
    /// <c>C_CloseSession</c> was entered while that call was still on the stack.
    /// </summary>
    private sealed class ParkingFake : FakeLowLevelPkcs11Library
    {
        internal readonly ManualResetEventSlim Entered = new(false);
        internal readonly ManualResetEventSlim Release = new(false);

        private volatile bool _inFlight;

        /// <summary>Set if a close was issued while a native call was still executing.</summary>
        internal volatile bool ClosedDuringNativeCall;

        private int _closes;
        internal int Closes => Volatile.Read(ref _closes);

        public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
        {
            _inFlight = true;
            Entered.Set();
            Release.Wait(Generous);
            _inFlight = false;
            return CKR.CKR_OK;
        }

        public override CKR C_CloseSession(NativeCULong session)
        {
            if (_inFlight)
                ClosedDuringNativeCall = true;
            Interlocked.Increment(ref _closes);
            return CKR.CKR_OK;
        }

        /// <summary>Releases the two gates. Callers join every thread before disposing the fake.</summary>
        public override void Dispose()
        {
            Entered.Dispose();
            Release.Dispose();
        }
    }

    private sealed record RaceOutcome(bool ClosedDuringNativeCall, int Closes, Exception? DisposeFailure);

    /// <summary>
    /// Parks a worker thread inside the native call, disposes the session from a second thread
    /// while it is parked, then lets the worker finish and reports what happened.
    /// </summary>
    private static RaceOutcome DisposeWhileACallIsInFlight()
    {
        using var fake = new ParkingFake();
        var session = new Pkcs11Session(fake, SessionId);

        Exception? disposeFailure = null;

        var worker = new Thread(() => session.GenerateRandom(8)) { IsBackground = true };
        var disposer = new Thread(() =>
        {
            try
            {
                session.Dispose();
            }
            catch (Exception ex)
            {
                disposeFailure = ex;
            }
        })
        { IsBackground = true };

        worker.Start();
        Assert.True(fake.Entered.Wait(Generous), "the worker never reached the native call");

        // The worker is now parked inside C_GenerateRandom holding the busy lock, so a Dispose
        // that skips the lock closes the session out from under it.
        disposer.Start();

        // Unblock the worker only after the disposer has had a chance to run. Yield rather than
        // sleep a fixed interval: correctness here is asserted on ordering, not on elapsed time —
        // a Dispose that ignores the lock has already closed by the time the worker returns.
        Thread.Yield();
        fake.Release.Set();

        Assert.True(worker.Join(Generous), "the worker thread did not finish");
        Assert.True(disposer.Join(Generous), "Dispose never returned — it is waiting on a lock nobody releases");

        return new RaceOutcome(fake.ClosedDuringNativeCall, fake.Closes, disposeFailure);
    }

    [Fact]
    public void Dispose_DoesNotCloseTheSessionWhileANativeCallIsInFlight()
    {
        RaceOutcome outcome = DisposeWhileACallIsInFlight();

        Assert.False(outcome.ClosedDuringNativeCall);
        Assert.Equal(1, outcome.Closes);   // still closed, just not until the call returned
    }

    /// <summary>
    /// Dispose has to wait for the busy lock, not take it the way every operation does:
    /// <see cref="Pkcs11Session.AcquireExclusive"/> throws on cross-thread contention, and Dispose
    /// usually runs from a <c>using</c> that is already unwinding, where a throw would replace the
    /// exception that started the unwind.
    /// </summary>
    [Fact]
    public void Dispose_DoesNotThrow_WhenAnotherThreadHoldsTheBusyLock()
    {
        RaceOutcome outcome = DisposeWhileACallIsInFlight();

        Assert.Null(outcome.DisposeFailure);
    }

    /// <summary>
    /// The busy lock is reentrant by design (secure helpers call the public operations they wrap).
    /// Disposing from inside an exclusive section on the same thread must therefore still close,
    /// not deadlock against a lock this very thread is holding.
    /// </summary>
    [Fact]
    public void Dispose_FromInsideAnExclusiveSection_OnTheSameThread_DoesNotDeadlock()
    {
        using var fake = new ParkingFake();
        fake.Release.Set();
        var session = new Pkcs11Session(fake, SessionId);

        using var completed = new ManualResetEventSlim(false);
        var thread = new Thread(() =>
        {
            using (session.AcquireExclusive(nameof(Dispose_FromInsideAnExclusiveSection_OnTheSameThread_DoesNotDeadlock)))
            {
                session.Dispose();
            }
            completed.Set();
        })
        { IsBackground = true };

        thread.Start();

        Assert.True(completed.Wait(Generous), "Dispose deadlocked against a lock its own thread held");
        Assert.True(thread.Join(Generous));
        Assert.Equal(1, fake.Closes);
    }
}
