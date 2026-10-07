using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal.SafeHandles;

/// <summary>
/// Cryptoki state belongs to the module, not to one load of it. A second load shares the first's
/// state (<c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c>), so <c>C_Finalize</c> must wait until no load of
/// the module is live. And since it can run long after <c>Dispose</c> returned, its failure is logged.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ModuleLoadsTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public void DisposingTheFirstLoad_LeavesTheSecondInitialized_AndTheLastOneFinalizes()
    {
        using var module = new SharedStateModule();
        Pkcs11Library first = module.Load();
        Pkcs11Library second = module.Load();

        first.Dispose();

        Assert.Equal(0, module.CallCount("C_Finalize"));
        Assert.Null(Record.Exception(() => second.GetInfo()));

        second.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    /// <summary>
    /// BL-083 as reported: the library that initialized the module is disposed while another library
    /// of the same module has a session open. That session must stay open and usable, and the module
    /// is finalized only after it and its library are gone.
    /// </summary>
    [Fact]
    public void DisposingTheFirstLoad_LeavesTheSecondLoadsSessionOpenAndUsable()
    {
        using var module = new SharedStateModule();
        Pkcs11Library first = module.Load();
        Pkcs11Library second = module.Load();
        var session = new Pkcs11Session(second.LowLevelLibrary!, (ulong)module.OpenSession());

        first.Dispose();

        Assert.Equal(64, session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(1), "data"u8).Length);
        Assert.Empty(module.Teardown);

        session.Dispose();
        second.Dispose();

        Assert.Equal(["C_CloseSession", "C_Finalize"], module.Teardown);
    }

    /// <summary>
    /// A load made while a disposed one still waits for a call in flight sees the old state as its own.
    /// The deferred <c>C_Finalize</c> must not then run under it.
    /// </summary>
    [Fact]
    public async Task DeferredFinalize_DoesNotTearDownALoadMadeMeanwhile()
    {
        using var module = new SharedStateModule { ParkFirstGetInfo = true };
        Pkcs11Library first = module.Load();
        Task call = Task.Run(() => first.GetInfo(), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the call never reached the module");

        first.Dispose();
        Pkcs11Library second = module.Load();
        module.Release.Set();
        await call.WaitAsync(Generous, Token);

        Assert.Equal(0, module.CallCount("C_Finalize"));
        Assert.Null(Record.Exception(() => second.GetInfo()));

        second.Dispose();

        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    [Fact]
    public void FailedFinalize_IsLogged()
    {
        using var module = new SharedStateModule { FinalizeRv = CKR.CKR_GENERAL_ERROR };
        var logger = new CapturingLogger();
        Pkcs11Library library = module.Load(new CapturingLoggerFactory(logger));

        library.Dispose();

        CapturingLogger.Entry entry = Assert.Single(logger.Entries, e => e.Message.Contains("C_Finalize", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(nameof(CKR.CKR_GENERAL_ERROR), entry.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A deferred <c>C_Finalize</c> runs when the call in flight releases the module. Its failure must not
    /// surface in that unrelated call, and nothing on that path calls the caller's logger: Dispose logs
    /// that the finalize was deferred, on its own thread.
    /// </summary>
    [Fact]
    public async Task DeferredFinalize_ThatFails_DoesNotSurfaceInTheCallThatReleasesTheModule()
    {
        using var module = new SharedStateModule { ParkFirstGetInfo = true, FinalizeRv = CKR.CKR_GENERAL_ERROR };
        var logger = new CapturingLogger();
        Pkcs11Library library = module.Load(new CapturingLoggerFactory(logger));
        Task call = Task.Run(() => library.GetInfo(), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the call never reached the module");

        library.Dispose();
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Information && e.Message.Contains("deferred", StringComparison.Ordinal));
        logger.Clear();

        module.Release.Set();
        await call.WaitAsync(Generous, Token);

        Assert.Equal(1, module.CallCount("C_Finalize"));
        Assert.Empty(logger.Entries);
    }

    // Pkcs11Library.Dispose end to end through the real low-level library: test doubles finalize at
    // once, so only a module like this one exercises the deferred path behind it.
    [Fact]
    public void LibraryDispose_ClosesItsSessionsBeforeFinalizing()
    {
        using var module = new SharedStateModule();
        Pkcs11Library library = module.Load();
        var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        library.Dispose();

        Assert.Equal(["C_CloseSession", "C_Finalize"], module.Teardown);
        session.Dispose();
    }

    /// <summary>
    /// A module with one Cryptoki state shared by every load: the first <c>C_Initialize</c> succeeds, the
    /// next see <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c>, and calls fail once it is finalized.
    /// </summary>
    private sealed class SharedStateModule : FakeModule
    {
        private int _initialized;

        public bool ParkFirstGetInfo { get; init; }
        public CKR FinalizeRv { get; init; } = CKR.CKR_OK;
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public List<string> Teardown { get; } = [];

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_Initialize(IntPtr pInitArgs)
            => Interlocked.Exchange(ref _initialized, 1) == 1 ? CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED : CKR.CKR_OK;

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            Teardown.Add("C_Finalize");
            Volatile.Write(ref _initialized, 0);
            return FinalizeRv;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Teardown.Add("C_CloseSession");
            return CKR.CKR_OK;
        }

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
            => Volatile.Read(ref _initialized) == 1 ? CKR.CKR_OK : CKR.CKR_CRYPTOKI_NOT_INITIALIZED;

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
        {
            if (Volatile.Read(ref _initialized) != 1)
                return CKR.CKR_CRYPTOKI_NOT_INITIALIZED;
            signatureLen = (NativeCULong)64UL;
            if (!signature.IsNull)
                signature.Span[..64].Fill(0xA5);
            return CKR.CKR_OK;
        }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            if (ParkFirstGetInfo && !Entered.IsSet)
            {
                Entered.Set();
                Release.Wait(Generous);
            }
            return Volatile.Read(ref _initialized) == 1 ? CKR.CKR_OK : CKR.CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    }
}
