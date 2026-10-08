using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// A module that refuses OS locking (<c>CKR_CANT_LOCK</c>) is initialized without it, which promises it
/// is never called concurrently (PKCS#11 v3.2 §5.4). The library keeps that promise by serializing every
/// call into the module, across every instance and session using it, and reports the mode through
/// <see cref="Pkcs11Library.SupportsConcurrentAccess"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ConcurrencyModeTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    // Long enough for an unserialized call to have reached the module; a serialized one never does.
    private static readonly TimeSpan WouldHaveEntered = TimeSpan.FromMilliseconds(300);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ModuleThatCannotLock_CallsAreSerialized()
    {
        using var module = new LockingModule { CannotLock = true };
        Pkcs11Library library = module.Load();
        Assert.False(library.SupportsConcurrentAccess);

        Task first = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Parked.Wait(Generous, Token), "the first call never reached the module");
        Task second = Task.Run(() => library.GetInfo(), Token);

        await Task.Delay(WouldHaveEntered, Token);
        Assert.False(second.IsCompleted);
        Assert.Equal(1, module.GetInfoCalls);

        module.Release.Set();
        await Task.WhenAll(first, second).WaitAsync(Generous, Token);
        Assert.Equal(1, module.PeakInFlight);
        library.Dispose();
    }

    // The promise is per module, not per instance: a second instance shares the first's state.
    [Fact]
    public async Task ModuleThatCannotLock_IsSerializedAcrossInstances()
    {
        using var module = new LockingModule { CannotLock = true };
        Pkcs11Library first = module.Load();
        Pkcs11Library second = module.Load();
        Assert.False(second.SupportsConcurrentAccess);

        Task parked = Task.Run(() => first.GetInfo(), Token);
        Assert.True(module.Parked.Wait(Generous, Token), "the first call never reached the module");
        Task other = Task.Run(() => second.GetInfo(), Token);

        await Task.Delay(WouldHaveEntered, Token);
        Assert.False(other.IsCompleted);

        module.Release.Set();
        await Task.WhenAll(parked, other).WaitAsync(Generous, Token);
        Assert.Equal(1, module.PeakInFlight);
        second.Dispose();
        first.Dispose();
    }

    [Fact]
    public async Task ModuleThatLocks_CallsRunConcurrently()
    {
        using var module = new LockingModule();
        Pkcs11Library library = module.Load();
        Assert.True(library.SupportsConcurrentAccess);

        Task first = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Parked.Wait(Generous, Token), "the first call never reached the module");
        await Task.Run(() => library.GetInfo(), Token).WaitAsync(Generous, Token);

        Assert.Equal(2, module.PeakInFlight);
        module.Release.Set();
        await first.WaitAsync(Generous, Token);
        library.Dispose();
    }

    // A session's C_CloseSession goes to the module without a ModuleCall; it must wait its turn too.
    [Fact]
    public async Task ModuleThatCannotLock_SessionCloseWaitsForTheCallInFlight()
    {
        using var module = new LockingModule { CannotLock = true };
        Pkcs11Library library = module.Load();
        var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        Task parked = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Parked.Wait(Generous, Token), "the first call never reached the module");
        Task close = Task.Run(session.Dispose, Token);

        await Task.Delay(WouldHaveEntered, Token);
        Assert.False(close.IsCompleted);
        Assert.Equal(0, module.CallCount("C_CloseSession"));

        module.Release.Set();
        await Task.WhenAll(parked, close).WaitAsync(Generous, Token);
        Assert.Equal(1, module.CallCount("C_CloseSession"));
        Assert.Equal(1, module.PeakInFlight);
        library.Dispose();
    }

    [Fact]
    public void ModuleThatCannotLock_BlockingWaitIsRefused_PollingWorks()
    {
        using var module = new LockingModule { CannotLock = true };
        Pkcs11Library library = module.Load();

        Assert.Throws<InvalidOperationException>(() => library.WaitForSlotEvent(nonBlocking: false));
        Assert.Null(library.WaitForSlotEvent(nonBlocking: true));
        Assert.Equal(1, module.CallCount("C_WaitForSlotEvent"));
        library.Dispose();
    }

    /// <summary>
    /// One Cryptoki state shared by every load. With <see cref="CannotLock"/> it answers a
    /// <c>C_Initialize</c> with arguments (asking for OS locking) with <c>CKR_CANT_LOCK</c>. The first
    /// <c>C_GetInfo</c> parks until released, and every module call records how many were in flight.
    /// </summary>
    private sealed class LockingModule : FakeModule
    {
        private int _initialized;
        private int _inFlight;
        private int _peakInFlight;
        private int _getInfoCalls;

        public bool CannotLock { get; init; }
        public ManualResetEventSlim Parked { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public int PeakInFlight => Volatile.Read(ref _peakInFlight);
        public int GetInfoCalls => Volatile.Read(ref _getInfoCalls);

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_Initialize(IntPtr pInitArgs)
        {
            if (Volatile.Read(ref _initialized) == 1)
                return CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED;
            if (CannotLock && pInitArgs != IntPtr.Zero)
                return CKR.CKR_CANT_LOCK;
            Volatile.Write(ref _initialized, 1);
            return CKR.CKR_OK;
        }

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            Volatile.Write(ref _initialized, 0);
            return CKR.CKR_OK;
        }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            Enter();
            try
            {
                if (Interlocked.Increment(ref _getInfoCalls) == 1)
                {
                    Parked.Set();
                    Release.Wait(Generous);
                }
                return CKR.CKR_OK;
            }
            finally
            {
                Interlocked.Decrement(ref _inFlight);
            }
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Enter();
            Interlocked.Decrement(ref _inFlight);
            return CKR.CKR_OK;
        }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot) => CKR.CKR_NO_EVENT;

        private void Enter()
        {
            int now = Interlocked.Increment(ref _inFlight);

            // Raise the recorded peak to now, unless another thread has already raised it as high.
            int peak = Volatile.Read(ref _peakInFlight);
            while (now > peak)
            {
                int seen = Interlocked.CompareExchange(ref _peakInFlight, now, peak);
                if (seen == peak)
                    break;
                peak = seen;
            }
        }
    }
}
