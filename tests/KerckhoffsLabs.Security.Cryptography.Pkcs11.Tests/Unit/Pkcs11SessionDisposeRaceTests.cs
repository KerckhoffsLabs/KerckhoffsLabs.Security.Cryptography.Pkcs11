using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Session.Dispose"/> logs out before closing its session. That logout must keep
/// the guarantee <c>Pkcs11SessionCoreDisposeRaceTests</c> pins for the session itself: wait for a call
/// in flight on another thread rather than throw. Taken through the throwing busy guard, the logout
/// made Dispose fail with "Concurrent access" before the session was ever closed, leaking it and
/// replacing whatever exception a surrounding <see langword="using"/> was unwinding.
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
    public async Task Dispose_WhileAnotherThreadIsMidCall_WaitsThenLogsOutAndClosesOnce()
    {
        using var fake = new ParkingFake();
        using var library = fake.Load();
        using var lowLevel = fake.LoadLowLevel();
        var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), new Pkcs11SessionCore(lowLevel, slotId: default, SessionId));

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
        Assert.Equal(1, fake.Logouts);
        Assert.Equal(1, fake.Closes);
        Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
    }

    // A dedicated thread, like the parked native call it races, and a task so that what it throws reaches
    // the test instead of ending the process.
    private static Task OnItsOwnThread(Action action)
        => Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    /// <summary>
    /// Holds <c>C_Logout</c> until another thread has tried a call on the session, and records the order of
    /// the calls that reach it.
    /// </summary>
    private sealed class GatedLogoutFake : FakeModule
    {
        internal readonly ManualResetEventSlim LoggingOut = new(false);
        internal readonly ManualResetEventSlim Attempted = new(false);

        private readonly List<string> _calls = [];

        internal string[] CallOrder
        {
            get { lock (_calls) return [.. _calls]; }
        }

        private void Record(string call)
        {
            lock (_calls) _calls.Add(call);
        }

        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            Record("C_GenerateRandom");
            return CKR.CKR_OK;
        }

        protected override CKR C_Logout(NativeCULong session)
        {
            Record("C_Logout");
            LoggingOut.Set();
            Attempted.Wait(Generous, TestContext.Current.CancellationToken);
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Record("C_CloseSession");
            return CKR.CKR_OK;
        }

        protected override void Disposing()
        {
            LoggingOut.Dispose();
            Attempted.Dispose();
        }
    }

    /// <summary>
    /// Holds the session core's "Dispose1" trace, logged as its close begins, until <see cref="Tried"/> is
    /// set: a call tried then runs before the close if the close is not under the logout's lock hold.
    /// </summary>
    private sealed class CloseGate : ILogger, ILoggerFactory
    {
        internal readonly ManualResetEventSlim Closing = new(false);
        internal readonly ManualResetEventSlim Tried = new(false);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!formatter(state, exception).EndsWith("::Dispose1", StringComparison.Ordinal))
                return;
            Closing.Set();
            Tried.Wait(Generous, TestContext.Current.CancellationToken);
        }

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        public ILogger CreateLogger(string categoryName) => this;
        public void AddProvider(ILoggerProvider provider) { }

        public void Dispose()
        {
            Closing.Dispose();
            Tried.Dispose();
        }
    }

    /// <summary>
    /// Dispose logs out and closes under one hold of the session's lock. Taken twice, a call on another
    /// thread could run between the two, on a session still open but logged out, where a private key it
    /// used had become invisible (<c>CKR_OBJECT_HANDLE_INVALID</c>). A call racing Dispose is refused as
    /// concurrent while Dispose holds the lock, and finds the session disposed after; none reaches the
    /// module once the logout has.
    /// </summary>
    [Fact]
    public async Task Dispose_CallRacingTheLogout_NeverRunsBetweenTheLogoutAndTheClose()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using var fake = new GatedLogoutFake();
        using var library = fake.Load();
        using var lowLevel = fake.LoadLowLevel();
        using var gate = new CloseGate();
        var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), new Pkcs11SessionCore(lowLevel, slotId: default, SessionId, gate));

        Task disposer = OnItsOwnThread(session.Dispose);
        Assert.True(fake.LoggingOut.Wait(Generous, token), "Dispose never reached C_Logout");

        // One call while C_Logout is in the module, one as the close begins, one after Dispose returns.
        var outcomes = new List<string>();
        Task caller = OnItsOwnThread(() =>
        {
            outcomes.Add(TryCall(session));
            fake.Attempted.Set();
            Assert.True(gate.Closing.Wait(Generous, token), "Dispose never began the close");
            outcomes.Add(TryCall(session));
            gate.Tried.Set();
        });

        await caller.WaitAsync(Generous, token);
        await disposer.WaitAsync(Generous, token);
        outcomes.Add(TryCall(session));

        Assert.Equal(["concurrent", "concurrent", "disposed"], outcomes);
        Assert.Equal(["C_Logout", "C_CloseSession"], fake.CallOrder);
    }

    private static string TryCall(Pkcs11Session session)
    {
        try
        {
            _ = session.GenerateRandom(8);
            return "ran";
        }
        catch (InvalidOperationException e) when (e.Message.Contains("Concurrent access", StringComparison.Ordinal))
        {
            return "concurrent";
        }
        catch (ObjectDisposedException)
        {
            return "disposed";
        }
    }

    /// <summary>
    /// A token that rejects the logout (already logged out, or one that never had a login — NSS's
    /// generic token answers <see cref="CKR.CKR_USER_NOT_LOGGED_IN"/>) must still have its session
    /// closed: the logout is best-effort, the close is not.
    /// </summary>
    [Fact]
    public void Dispose_WhenTheLogoutIsRejected_StillClosesTheSession()
    {
        using var fake = new RejectingLogoutFake();
        using var library = fake.Load();
        using var lowLevel = fake.LoadLowLevel();
        var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), new Pkcs11SessionCore(lowLevel, slotId: default, SessionId));

        session.Dispose();

        Assert.Equal(1, fake.Closes);
    }

    private sealed class RejectingLogoutFake : FakeModule
    {
        internal int Closes;

        protected override CKR C_Logout(NativeCULong session) => CKR.CKR_USER_NOT_LOGGED_IN;

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Closes++;
            return CKR.CKR_OK;
        }
    }
}
