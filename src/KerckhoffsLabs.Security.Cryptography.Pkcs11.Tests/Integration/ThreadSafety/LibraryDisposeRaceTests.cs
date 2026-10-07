using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// Disposing a <see cref="Pkcs11Library"/> while another thread is inside a module call. The module
/// parks that call on an event, so the race is reproduced deterministically: the test controls exactly
/// when the call is in flight, and the module records what the library did to it meanwhile.
/// </summary>
/// <remarks>
/// Every call holds a reference on the module handle, and every session operation one on its session
/// handle, so <c>C_Finalize</c>, the unmap and <c>C_CloseSession</c> all wait for a call in flight.
/// Neither test depends on how that is achieved: Dispose may return at once and defer the teardown,
/// or wait for the call to finish.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LibraryDisposeRaceTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Dispose_DoesNotFinalizeTheModule_UnderACallWithoutASession()
    {
        using var module = new ParkingModule();
        Pkcs11Library library = module.Load();

        Task call = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the call never reached the module");

        Task dispose = Task.Run(library.Dispose, Token);
        await WaitBriefly(dispose); // Dispose may defer the teardown or wait for the call; both are fine

        module.Release.Set();
        await call.WaitAsync(Generous, Token);
        await dispose.WaitAsync(Generous, Token);

        Assert.False(module.FinalizedWhileInFlight, "C_Finalize ran while a call was still inside the module.");
        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    [Fact]
    public async Task Dispose_DoesNotCloseASession_UnderACallOnIt()
    {
        using var module = new ParkingModule();
        Pkcs11Library library = module.Load();
        var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        Task call = Task.Run(() => session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(1), "data"u8), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the call never reached the module");

        Task dispose = Task.Run(library.Dispose, Token);
        await WaitBriefly(dispose);

        module.Release.Set();
        // The parked call is the length probe; the library may refuse the fill call that follows,
        // because it was disposed meanwhile. That is correct; only what happened under the call counts.
        Exception? outcome = await Record.ExceptionAsync(() => call.WaitAsync(Generous, Token));
        Assert.True(outcome is null or ObjectDisposedException, $"unexpected outcome: {outcome}");
        await dispose.WaitAsync(Generous, Token);
        session.Dispose();

        Assert.False(module.ClosedWhileInFlight, "C_CloseSession ran while a call on that session was still inside the module.");
        Assert.False(module.FinalizedWhileInFlight, "C_Finalize ran while a call was still inside the module.");
    }

    // SafeHandle only marks itself closed when its last reference goes, so while a call is in flight a
    // disposed module would still let a new call in. It must be turned away like any call after Dispose.
    [Fact]
    public async Task Dispose_TurnsAwayANewCall_WhileAnotherIsStillInFlight()
    {
        using var module = new ParkingModule();
        Pkcs11Library library = module.Load();
        LowLevelPkcs11Library lowLevel = (LowLevelPkcs11Library)library.LowLevelLibrary!;

        Task call = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the call never reached the module");
        library.Dispose();

        CK_INFO info = default;
        Assert.Throws<ObjectDisposedException>(() => lowLevel.C_GetInfo(ref info));

        module.Release.Set();
        await call.WaitAsync(Generous, Token);
        Assert.Equal(1, module.CallCount("C_GetInfo"));
        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    // The one call C_Finalize is meant to interrupt: PKCS#11 has it wake a blocking C_WaitForSlotEvent
    // with CKR_CRYPTOKI_NOT_INITIALIZED. Disposing must do that, not wait for an event that may never come.
    [Fact]
    public async Task Dispose_WakesABlockingWaitForSlotEvent()
    {
        using var module = new WaitingModule();
        Pkcs11Library library = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => library.WaitForSlotEvent(nonBlocking: false)), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        library.Dispose();

        Exception? outcome = await wait.WaitAsync(Generous, Token);
        var e = Assert.IsType<Pkcs11Exception>(outcome, exactMatch: false);
        Assert.Equal(CKR.CKR_CRYPTOKI_NOT_INITIALIZED, e.ReturnValue);
        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    private static async Task WaitBriefly(Task task)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(1), Token); }
        catch (TimeoutException) { /* Dispose waits for the call to finish: also correct */ }
    }

    /// <summary>
    /// A workspace's dispose logs out through <c>LogoutForDispose</c>, which waits for the session lock
    /// rather than going through <c>AcquireExclusive</c>. It must still hold the session's handle, as every
    /// other operation does, or a library disposed meanwhile closes the session under the logout.
    /// </summary>
    [Fact]
    public async Task Dispose_DoesNotCloseASession_UnderItsLogoutForDispose()
    {
        using var module = new ParkingModule();
        Pkcs11Library library = module.Load();
        var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        Task logout = Task.Run(session.LogoutForDispose, Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the logout never reached the module");

        Task dispose = Task.Run(library.Dispose, Token);
        await WaitBriefly(dispose);

        module.Release.Set();
        await logout.WaitAsync(Generous, Token);
        await dispose.WaitAsync(Generous, Token);
        session.Dispose();

        Assert.False(module.ClosedWhileInFlight, "C_CloseSession ran while the session's logout was still inside the module.");
        Assert.Equal(1, module.CallCount("C_CloseSession"));
    }

    /// <summary>
    /// Parks the first <c>C_GetInfo</c>, <c>C_Sign</c> or <c>C_Logout</c> until <see cref="Release"/> is set, and records
    /// whether <c>C_Finalize</c> or <c>C_CloseSession</c> arrived while it was parked.
    /// </summary>
    private sealed class ParkingModule : FakeModule
    {
        private int _inFlight;

        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public bool FinalizedWhileInFlight { get; private set; }
        public bool ClosedWhileInFlight { get; private set; }

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            FinalizedWhileInFlight |= Volatile.Read(ref _inFlight) != 0;
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            ClosedWhileInFlight |= Volatile.Read(ref _inFlight) != 0;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            Park();
            info.CryptokiVersion = new CK_VERSION { Major = 2, Minor = 40 };
            return CKR.CKR_OK;
        }

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Logout(NativeCULong session)
        {
            Park();
            return CKR.CKR_OK;
        }

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
        {
            Park();
            signatureLen = (NativeCULong)64UL;
            return CKR.CKR_OK;
        }

        private void Park()
        {
            if (Entered.IsSet)
                return; // only the first call parks
            Interlocked.Exchange(ref _inFlight, 1);
            Entered.Set();
            Release.Wait(Generous);
            Interlocked.Exchange(ref _inFlight, 0);
        }
    }

    /// <summary>Blocks in <c>C_WaitForSlotEvent</c> until <c>C_Finalize</c> arrives, as a module does.</summary>
    private sealed class WaitingModule : FakeModule
    {
        private readonly ManualResetEventSlim _finalized = new();

        public ManualResetEventSlim Waiting { get; } = new();

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            _finalized.Set();
            return CKR.CKR_OK;
        }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
        {
            Waiting.Set();
            return _finalized.Wait(Generous) ? CKR.CKR_CRYPTOKI_NOT_INITIALIZED : CKR.CKR_NO_EVENT;
        }
    }
}
