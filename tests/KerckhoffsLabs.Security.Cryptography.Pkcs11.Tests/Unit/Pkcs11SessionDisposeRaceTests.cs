using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Session.Dispose"/> keeps the guarantee <c>Pkcs11SessionCoreDisposeRaceTests</c> pins for
/// the session itself: it waits for a call in flight on another thread rather than throw, and it never sends
/// <c>C_Logout</c> (a login ends with its last holder, not with a session). Throwing on contention would leak
/// the session and replace whatever exception a surrounding <see langword="using"/> was unwinding.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionDisposeRaceTests
{
    private const ulong SessionId = 42;

    /// <summary>Upper bound for a wait that is only ever reached when something has gone wrong.</summary>
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Parks inside <c>C_GenerateRandom</c> until released, and records whether <c>C_Logout</c> or
    /// <c>C_CloseSession</c> was entered while that call was still on the stack.
    /// </summary>
    private sealed class ParkingFake : FakeModule
    {
        internal readonly ManualResetEventSlim Entered = new(false);
        internal readonly ManualResetEventSlim Release = new(false);

        private volatile bool _inFlight;

        /// <summary>Set if a logout or close was issued while a native call was still executing.</summary>
        internal volatile bool TouchedDuringNativeCall;

        private int _logouts;
        internal int Logouts => Volatile.Read(ref _logouts);

        private int _closes;
        internal int Closes => Volatile.Read(ref _closes);

        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            _inFlight = true;
            Entered.Set();
            Release.Wait(Generous, TestContext.Current.CancellationToken);
            _inFlight = false;
            return CKR.CKR_OK;
        }

        protected override CKR C_Logout(NativeCULong session)
        {
            if (_inFlight)
                TouchedDuringNativeCall = true;
            Interlocked.Increment(ref _logouts);
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            if (_inFlight)
                TouchedDuringNativeCall = true;
            Interlocked.Increment(ref _closes);
            return CKR.CKR_OK;
        }

        /// <summary>Releases the two gates. Callers join every thread before disposing the fake.</summary>
        protected override void Disposing()
        {
            Entered.Dispose();
            Release.Dispose();
        }
    }

    [Fact]
    public async Task Dispose_WhileAnotherThreadIsMidCall_WaitsThenClosesOnce_AndNeverLogsOut()
    {
        using var fake = new ParkingFake();
        using var library = fake.Load();
        using var lowLevel = fake.LoadLowLevel();
        var session = new Pkcs11Session(library, new Pkcs11Slot(library, slotId: 1), new Pkcs11SessionCore(lowLevel, slotId: default, SessionId));

        Task worker = OnItsOwnThread(() => _ = session.GenerateRandom(8));
        Assert.True(fake.Entered.Wait(Generous, TestContext.Current.CancellationToken), "the worker never reached the native call");

        // The worker is parked inside C_GenerateRandom holding the busy lock. Yield, then release:
        // ordering is what is asserted, so a Dispose that does not wait has already failed or
        // reached the module by the time the worker returns.
        Task disposer = OnItsOwnThread(session.Dispose);
        Thread.Yield();
        fake.Release.Set();

        // Awaiting rethrows what the task threw, so a Dispose that fails fails the test here; one that
        // waits on a lock nobody releases times out.
        await worker.WaitAsync(Generous, TestContext.Current.CancellationToken);
        await disposer.WaitAsync(Generous, TestContext.Current.CancellationToken);

        Assert.False(fake.TouchedDuringNativeCall);
        Assert.Equal(0, fake.Logouts);
        Assert.Equal(1, fake.Closes);
        Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
    }

    // A dedicated thread, like the parked native call it races, and a task so that what it throws reaches
    // the test instead of ending the process.
    private static Task OnItsOwnThread(Action action)
        => Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
}
