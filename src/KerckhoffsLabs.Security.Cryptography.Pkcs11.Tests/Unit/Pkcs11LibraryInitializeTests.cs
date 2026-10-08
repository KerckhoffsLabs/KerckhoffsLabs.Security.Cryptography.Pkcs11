using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library's private Initialize() fallback and its failure path. The plain
/// CKR_OK path and the immediate CKR_CRYPTOKI_ALREADY_INITIALIZED short-circuit are already exercised by
/// every other test that constructs a Pkcs11Library; this covers the CKF_OS_LOCKING_OK-refused retry (and
/// its own ALREADY_INITIALIZED variant) plus what happens when C_Initialize never succeeds.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LibraryInitializeTests
{
    private sealed class InitializeModule : FakeModule
    {
        public int InitializeCalls { get; private set; }
        public int FinalizeCalls { get; private set; }
        public bool? LastCallUsedOsLocking { get; private set; }
        public Func<int, CKR> RvForCall = _ => CKR.CKR_OK;

        protected override CKR C_Initialize(IntPtr pInitArgs)
        {
            InitializeCalls++;
            LastCallUsedOsLocking = pInitArgs != IntPtr.Zero;
            return RvForCall(InitializeCalls);
        }

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            FinalizeCalls++;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void CantLock_RetriesWithoutOsLocking_AndSucceeds()
    {
        using var fake = new InitializeModule { RvForCall = call => call == 1 ? CKR.CKR_CANT_LOCK : CKR.CKR_OK };
        var library = fake.Load();

        Assert.Equal(2, fake.InitializeCalls);
        Assert.False(fake.LastCallUsedOsLocking); // retry passes null args, not CKF_OS_LOCKING_OK

        library.Dispose();
        Assert.Equal(1, fake.FinalizeCalls); // this instance drove C_Initialize to CKR_OK: it owns finalize
    }

    [Fact]
    public void CantLock_RetryReportsAlreadyInitialized_DisposeSkipsFinalize()
    {
        using var fake = new InitializeModule
        {
            RvForCall = call => call == 1 ? CKR.CKR_CANT_LOCK : CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED,
        };
        var library = fake.Load();

        Assert.Equal(2, fake.InitializeCalls);

        library.Dispose();
        Assert.Equal(0, fake.FinalizeCalls); // another owner initialized; must not tear down their state
    }

    [Fact]
    public void InitializeNeverSucceeds_LoadRethrows_AndNeverFinalizes()
    {
        using var fake = new InitializeModule { RvForCall = _ => CKR.CKR_GENERAL_ERROR };

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => fake.Load());

        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
        Assert.Equal(1, fake.InitializeCalls);
        Assert.Equal(0, fake.FinalizeCalls); // C_Initialize never succeeded, so there is nothing to tear down
    }
}
