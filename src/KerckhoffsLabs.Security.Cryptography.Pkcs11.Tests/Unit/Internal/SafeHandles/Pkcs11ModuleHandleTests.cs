using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal.SafeHandles;

/// <summary>
/// <see cref="Pkcs11ModuleHandle"/> owns the module: calls hold a reference on it, sessions hold one for
/// their lifetime, and <c>C_Finalize</c> runs on the last release, never before.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11ModuleHandleTests
{
    [Fact]
    public void CallAfterDispose_ThrowsObjectDisposed()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.Dispose();

        CK_INFO info = default;
        Assert.Throws<ObjectDisposedException>(() => lowLevel.C_GetInfo(ref info));
        Assert.Equal(0, module.CallCount("C_GetInfo"));
    }

    [Fact]
    public void FinalizeOnLastRelease_FinalizesOnce_WhenTheLibraryIsDisposed()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Initialize(null));

        lowLevel.FinalizeOnLastRelease();
        Assert.Equal(0, module.CallCount("C_Finalize"));
        lowLevel.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    [Fact]
    public void FinalizeOnLastRelease_WaitsForAnOpenSession_ThenClosesItFirst()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);
        var session = new Pkcs11SessionHandle(lowLevel, module.OpenSession());

        lowLevel.FinalizeOnLastRelease();
        lowLevel.Dispose();
        Assert.Equal(0, module.CallCount("C_Finalize"));

        session.Dispose();

        Assert.Equal(["C_CloseSession", "C_Finalize"], module.Teardown);
    }

    [Fact]
    public void ModuleInitializedElsewhere_IsNeverFinalized()
    {
        using var module = new RecordingModule { InitializeRv = CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED };
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);

        lowLevel.FinalizeOnLastRelease();
        lowLevel.Dispose();

        Assert.Equal(0, module.CallCount("C_Finalize"));
    }

    /// <summary>
    /// An abandoned session's finalizer can run after its library's. The session still holds a module
    /// reference, so it must still close: it used to go through the disposed library and be turned away.
    /// </summary>
    [Fact]
    public void SessionReleasedAfterTheLibrary_IsStillClosed()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        var session = new Pkcs11SessionHandle(lowLevel, module.OpenSession());

        lowLevel.Dispose();
        session.Dispose();

        Assert.Equal(1, module.CallCount("C_CloseSession"));
    }

    [Fact]
    public void BindThatFailsToBuildTheTable_Rethrows_AndCountsNoLoadOfTheModule()
    {
        using var module = new RecordingModule();

        Assert.Throws<InvalidOperationException>(
            () => Pkcs11ModuleHandle.Bind(() => throw new InvalidOperationException("no table"), identity: module));

        // Had the failed bind counted as a live load of this module, the finalize below would be handed to
        // it and never run.
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);
        lowLevel.FinalizeOnLastRelease();
        lowLevel.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    // Whether the finalize on release was asked for before or after the explicit C_Finalize, it is not owed
    // once the module has been finalized.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExplicitFinalize_IsRemembered_SoDisposeDoesNotFinalizeAgain(bool requestedBeforeTheExplicitFinalize)
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);

        if (requestedBeforeTheExplicitFinalize)
            lowLevel.FinalizeOnLastRelease();
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Finalize(IntPtr.Zero));
        if (!requestedBeforeTheExplicitFinalize)
            lowLevel.FinalizeOnLastRelease();
        lowLevel.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    /// <summary>
    /// The first load hands its finalize to a second, still-live load of the same module. That load then
    /// finalizes the module itself, so the finalize it was handed is no longer owed when it goes.
    /// </summary>
    [Fact]
    public void ExplicitFinalize_CancelsAFinalizeHandedOverByAnotherLoad()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library first = module.LoadLowLevel();
        LowLevelPkcs11Library second = module.LoadLowLevel();
        Assert.Equal(CKR.CKR_OK, first.C_Initialize(null));
        Assert.Equal(CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED, second.C_Initialize(null));

        first.FinalizeOnLastRelease();
        first.Dispose();
        Assert.Equal(0, module.CallCount("C_Finalize"));

        Assert.Equal(CKR.CKR_OK, second.C_Finalize(IntPtr.Zero));
        second.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    /// <summary>
    /// Released without anyone asking for <c>C_Finalize</c> (a library that was never disposed): the module
    /// this handle initialized is left as it is, neither finalized nor unmapped.
    /// </summary>
    [Fact]
    public void AbandonedInitializedModule_IsNotFinalized()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);

        lowLevel.Dispose();

        Assert.True(lowLevel.Module.IsClosed);
        Assert.Equal(0, module.CallCount("C_Finalize"));
    }

    // Asking for the finalize is not disposing: a call that ends before Dispose must not run it early.
    [Fact]
    public void FinalizeRequested_ACallEndingBeforeDispose_DoesNotFinalizeEarly()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.C_Initialize(null);
        lowLevel.FinalizeOnLastRelease();

        CK_INFO info = default;
        Assert.Equal(CKR.CKR_OK, lowLevel.C_GetInfo(ref info));
        Assert.Equal(0, module.CallCount("C_Finalize"));

        lowLevel.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    // A failed C_CloseSession is reported by the session's release, not thrown, so closing every tracked
    // session carries on past it.
    [Fact]
    public void CloseAllTrackedSessions_CarriesOnPastASessionThatFailsToClose()
    {
        using var module = new RecordingModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        NativeCULong failing = module.OpenSession();
        _ = new Pkcs11SessionHandle(lowLevel, failing);
        _ = new Pkcs11SessionHandle(lowLevel, module.OpenSession());
        module.FailingClose = failing;

        lowLevel.Module.CloseAllTrackedSessions();

        Assert.Equal(2, module.CallCount("C_CloseSession"));
        Assert.Equal(0, lowLevel.Module.TrackedSessionCount);
        lowLevel.Dispose();
    }

    /// <summary>
    /// One Cryptoki state shared by every load, as a real module has: the first <c>C_Initialize</c> succeeds,
    /// later ones see <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c> until <c>C_Finalize</c>.
    /// </summary>
    private sealed class RecordingModule : FakeModule
    {
        private int _initialized;

        public CKR InitializeRv { get; init; } = CKR.CKR_OK;

        /// <summary>A session whose <c>C_CloseSession</c> fails with <c>CKR_DEVICE_ERROR</c>.</summary>
        public NativeCULong? FailingClose { get; set; }
        public List<string> Teardown { get; } = [];

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_Initialize(IntPtr pInitArgs)
            => InitializeRv != CKR.CKR_OK ? InitializeRv
                : Interlocked.Exchange(ref _initialized, 1) == 1 ? CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED : CKR.CKR_OK;

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            Teardown.Add("C_Finalize");
            Volatile.Write(ref _initialized, 0);
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Teardown.Add("C_CloseSession");
            return session == FailingClose ? CKR.CKR_DEVICE_ERROR : CKR.CKR_OK;
        }

        protected override CKR C_GetInfo(ref CK_INFO info) => CKR.CKR_OK;
    }
}
