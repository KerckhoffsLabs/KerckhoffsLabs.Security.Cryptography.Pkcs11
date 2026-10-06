using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
/// Both tests fail today. <c>Pkcs11Library.Dispose</c> closes tracked sessions and calls
/// <c>C_Finalize</c> immediately, guarded only by a disposed flag the in-flight call already passed;
/// with a real module the next step, <c>NativeLibrary.Free</c>, unmaps the code that call is running.
/// They are gated off by <see cref="DisposeRaceFixed"/> until the module and session handles hold a
/// reference for every call in flight, and are the acceptance tests for that change. Neither depends
/// on how the fix behaves: Dispose may return at once and defer the teardown, or wait for the call to
/// finish.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LibraryDisposeRaceTests
{
    // The fix that makes every call in flight hold a reference on the module and session handles flips
    // this to true, which turns both tests on. A static [Fact(Skip = "...")] (flagged by xUnit1004)
    // hard-disables a test with no named, auditable gate; [Fact(SkipUnless = ...)] ties it to this
    // property instead, matching the suite's other permanently-off gates.
    public static bool DisposeRaceFixed => false;

    private const string SkipReason =
        "Reproduces the dispose race: Pkcs11Library.Dispose tears the module down under a call in flight. " +
        "Set DisposeRaceFixed in the fix that makes every call in flight hold a reference on the module and session handles.";

    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact(SkipUnless = nameof(DisposeRaceFixed), Skip = SkipReason)]
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

    [Fact(SkipUnless = nameof(DisposeRaceFixed), Skip = SkipReason)]
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

    private static async Task WaitBriefly(Task task)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(1), Token); }
        catch (TimeoutException) { /* Dispose waits for the call to finish: also correct */ }
    }

    /// <summary>
    /// Parks the first <c>C_GetInfo</c> or <c>C_Sign</c> until <see cref="Release"/> is set, and records
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
}
