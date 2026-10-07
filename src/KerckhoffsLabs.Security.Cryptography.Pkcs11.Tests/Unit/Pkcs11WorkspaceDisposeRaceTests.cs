using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Workspace.Dispose"/> logs out before closing its session. That logout must keep
/// the guarantee <c>Pkcs11SessionDisposeRaceTests</c> pins for the session itself: wait for a call
/// in flight on another thread rather than throw. Taken through the throwing busy guard, the logout
/// made Dispose fail with "Concurrent access" before the session was ever closed, leaking it and
/// replacing whatever exception a surrounding <c>using</c> was unwinding.
/// </summary>
public sealed class Pkcs11WorkspaceDisposeRaceTests
{
    private const ulong SessionId = 42;

    /// <summary>Upper bound for a wait that is only ever reached when something has gone wrong.</summary>
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Parks inside <c>C_GenerateRandom</c> until released, and records whether <c>C_Logout</c> or
    /// <c>C_CloseSession</c> was entered while that call was still on the stack.
    /// </summary>
    private sealed class ParkingFake : FakeLowLevelPkcs11Library
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

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            _inFlight = true;
            Entered.Set();
            Release.Wait(Generous);
            _inFlight = false;
            return CKR.CKR_OK;
        }

        public override CKR C_Logout(NativeCULong session)
        {
            if (_inFlight)
                TouchedDuringNativeCall = true;
            Interlocked.Increment(ref _logouts);
            return CKR.CKR_OK;
        }

        public override CKR C_CloseSession(NativeCULong session)
        {
            if (_inFlight)
                TouchedDuringNativeCall = true;
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

    [Fact]
    public async Task Dispose_WhileAnotherThreadIsMidCall_WaitsThenLogsOutAndClosesOnce()
    {
        using var fake = new ParkingFake();
        using var library = new Pkcs11Library(fake);
        var workspace = new Pkcs11Workspace(library, new Pkcs11Slot(fake, slotId: 1), new Pkcs11Session(fake, SessionId));

        Task worker = OnItsOwnThread(() => _ = workspace.GenerateRandom(8));
        Assert.True(fake.Entered.Wait(Generous, TestContext.Current.CancellationToken), "the worker never reached the native call");

        // The worker is parked inside C_GenerateRandom holding the busy lock. Yield, then release:
        // ordering is what is asserted, so a Dispose that does not wait has already failed or
        // reached the module by the time the worker returns.
        Task disposer = OnItsOwnThread(workspace.Dispose);
        Thread.Yield();
        fake.Release.Set();

        // Awaiting rethrows what the task threw, so a Dispose that fails fails the test here; one that
        // waits on a lock nobody releases times out.
        await worker.WaitAsync(Generous, TestContext.Current.CancellationToken);
        await disposer.WaitAsync(Generous, TestContext.Current.CancellationToken);

        Assert.False(fake.TouchedDuringNativeCall);
        Assert.Equal(1, fake.Logouts);
        Assert.Equal(1, fake.Closes);
        Assert.Throws<ObjectDisposedException>(() => workspace.GetSessionInfo());
    }

    // A dedicated thread, like the parked native call it races, and a task so that what it throws reaches
    // the test instead of ending the process.
    private static Task OnItsOwnThread(Action action)
        => Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    /// <summary>
    /// A token that rejects the logout (already logged out, or one that never had a login — NSS's
    /// generic token answers <see cref="CKR.CKR_USER_NOT_LOGGED_IN"/>) must still have its session
    /// closed: the logout is best-effort, the close is not.
    /// </summary>
    [Fact]
    public void Dispose_WhenTheLogoutIsRejected_StillClosesTheSession()
    {
        using var fake = new RejectingLogoutFake();
        using var library = new Pkcs11Library(fake);
        var workspace = new Pkcs11Workspace(library, new Pkcs11Slot(fake, slotId: 1), new Pkcs11Session(fake, SessionId));

        workspace.Dispose();

        Assert.Equal(1, fake.Closes);
    }

    private sealed class RejectingLogoutFake : FakeLowLevelPkcs11Library
    {
        internal int Closes;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_Logout(NativeCULong session) => CKR.CKR_USER_NOT_LOGGED_IN;

        public override CKR C_CloseSession(NativeCULong session)
        {
            Closes++;
            return CKR.CKR_OK;
        }
    }
}
