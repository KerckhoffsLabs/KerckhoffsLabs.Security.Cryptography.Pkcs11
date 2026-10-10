using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

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
        Pkcs11Library library = module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(logger) });

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
        Pkcs11Library library = module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(logger) });
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
    /// A test module is identified by the object whose method resolves its exports, and a static method
    /// has none: then the resolver itself is the identity. Two delegates for the same static method are
    /// equal, so two loads through them are one module and share its Cryptoki state.
    /// </summary>
    [Fact]
    public void LoadsThroughAStaticResolver_ShareTheModulesState()
    {
        StaticModule.Install();
        try
        {
            Pkcs11Library first = new(new Func<string, IntPtr>(StaticModule.Resolve));
            Pkcs11Library second = new(new Func<string, IntPtr>(StaticModule.Resolve));

            first.Dispose();
            Assert.Equal(0, StaticModule.Finalizes);

            second.Dispose();
            Assert.Equal(1, StaticModule.Finalizes);
        }
        finally
        {
            StaticModule.Uninstall();
        }
    }

    /// <summary>
    /// A v2.40 module whose exports come from a static method, so its resolver has no target. Like
    /// <see cref="SharedStateModule"/>, its Cryptoki state is shared by every load.
    /// </summary>
    private static unsafe class StaticModule
    {
        private static IntPtr s_functionList;
        private static int s_initialized;
        private static int s_finalizes;

        public static int Finalizes => Volatile.Read(ref s_finalizes);

        public static void Install()
        {
            s_initialized = 0;
            s_finalizes = 0;
            s_functionList = NativeFunctionList.Allocate(2, 40, CryptokiTable.V240SlotCount, new Dictionary<string, IntPtr>
            {
                [nameof(CryptokiTable.C_Initialize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&Initialize,
                [nameof(CryptokiTable.C_Finalize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&FinalizeLibrary,
            });
        }

        public static void Uninstall()
        {
            Marshal.FreeHGlobal(s_functionList);
            s_functionList = IntPtr.Zero;
        }

        public static IntPtr Resolve(string name)
            => name == "C_GetFunctionList" ? (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)&GetFunctionList : IntPtr.Zero;

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static NativeCULong GetFunctionList(IntPtr* functionList)
        {
            *functionList = s_functionList;
            return Rv(CKR.CKR_OK);
        }

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static NativeCULong Initialize(void* initArgs)
            => Rv(Interlocked.Exchange(ref s_initialized, 1) == 1 ? CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED : CKR.CKR_OK);

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static NativeCULong FinalizeLibrary(void* reserved)
        {
            Interlocked.Increment(ref s_finalizes);
            Volatile.Write(ref s_initialized, 0);
            return Rv(CKR.CKR_OK);
        }

        private static NativeCULong Rv(CKR rv) => (NativeCULong)(ulong)rv;
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
