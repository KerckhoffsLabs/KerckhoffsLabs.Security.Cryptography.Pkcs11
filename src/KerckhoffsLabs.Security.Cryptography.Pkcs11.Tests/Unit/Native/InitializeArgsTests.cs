using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// What the module receives in <c>C_Initialize</c>: a <c>CK_C_INITIALIZE_ARGS</c> asking for OS locking,
/// with no mutex callbacks (they are not supported), laid out as this platform's headers lay it out —
/// Pack=1 on Windows. The layout itself is checked against the C compiler by <c>AbiOracleTests</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class InitializeArgsTests
{
    [Fact]
    public void Initialize_PassesOsLockingWithNoMutexCallbacks()
    {
        using var module = new ArgsModule();
        Pkcs11Library library = module.Load();

        CK_C_INITIALIZE_ARGS args = Assert.Single(module.Received)!.Value;
        Assert.Equal(CKF.CKF_OS_LOCKING_OK, (ulong)args.Flags);
        Assert.Equal(IntPtr.Zero, args.CreateMutex);
        Assert.Equal(IntPtr.Zero, args.DestroyMutex);
        Assert.Equal(IntPtr.Zero, args.LockMutex);
        Assert.Equal(IntPtr.Zero, args.UnlockMutex);
        library.Dispose();
    }

    // A module that refuses OS locking is initialized again with no arguments at all.
    [Fact]
    public void ModuleThatCannotLock_IsInitializedAgainWithNullArguments()
    {
        using var module = new ArgsModule { CannotLock = true };
        Pkcs11Library library = module.Load();

        Assert.Equal(2, module.Received.Count);
        Assert.NotNull(module.Received[0]);
        Assert.Null(module.Received[1]);
        library.Dispose();
    }

    private sealed class ArgsModule : FakeModule
    {
        public bool CannotLock { get; init; }

        // Each C_Initialize's arguments, read while the call is in progress: null for a NULL pInitArgs.
        public List<CK_C_INITIALIZE_ARGS?> Received { get; } = [];

        protected override CKR C_Initialize(IntPtr pInitArgs)
        {
            Received.Add(pInitArgs == IntPtr.Zero ? null : UnmanagedMemory.Read<CK_C_INITIALIZE_ARGS>(pInitArgs));
            return CannotLock && pInitArgs != IntPtr.Zero ? CKR.CKR_CANT_LOCK : CKR.CKR_OK;
        }
    }
}
