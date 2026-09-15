using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library's private Initialize() fallback and the
/// (ILowLevelPkcs11Library) test-seam constructor's failure path. The plain CKR_OK path and the
/// immediate CKR_CRYPTOKI_ALREADY_INITIALIZED short-circuit are already exercised by every other
/// test that constructs a Pkcs11Library; this covers the CKF_OS_LOCKING_OK-refused retry (and its
/// own ALREADY_INITIALIZED variant) plus what happens when C_Initialize never succeeds.
/// </summary>
public sealed class Pkcs11LibraryInitializeTests
{
    private sealed class InitializeFake : NotSupportedPkcs11Library
    {
        public int InitializeCalls { get; private set; }
        public int FinalizeCalls { get; private set; }
        public bool? LastCallUsedOsLocking { get; private set; }
        public bool DisposeCalled { get; private set; }
        public Func<int, CKR> RvForCall = _ => CKR.CKR_OK;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs)
        {
            InitializeCalls++;
            LastCallUsedOsLocking = initArgs is not null;
            return RvForCall(InitializeCalls);
        }

        public override CKR C_Finalize(IntPtr reserved)
        {
            FinalizeCalls++;
            return CKR.CKR_OK;
        }

        public override void Dispose() => DisposeCalled = true;
    }

    [Fact]
    public void CantLock_RetriesWithoutOsLocking_AndSucceeds()
    {
        var fake = new InitializeFake { RvForCall = call => call == 1 ? CKR.CKR_CANT_LOCK : CKR.CKR_OK };
        var library = new Pkcs11Library(fake);

        Assert.Equal(2, fake.InitializeCalls);
        Assert.False(fake.LastCallUsedOsLocking); // retry passes null args, not CKF_OS_LOCKING_OK

        library.Dispose();
        Assert.Equal(1, fake.FinalizeCalls); // this instance drove C_Initialize to CKR_OK: it owns finalize
    }

    [Fact]
    public void CantLock_RetryReportsAlreadyInitialized_DisposeSkipsFinalize()
    {
        var fake = new InitializeFake
        {
            RvForCall = call => call == 1 ? CKR.CKR_CANT_LOCK : CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED,
        };
        var library = new Pkcs11Library(fake);

        Assert.Equal(2, fake.InitializeCalls);

        library.Dispose();
        Assert.Equal(0, fake.FinalizeCalls); // another owner initialized; must not tear down their state
    }

    [Fact]
    public void InitializeNeverSucceeds_TestSeamCtor_DisposesLowLevelAndRethrows()
    {
        var fake = new InitializeFake { RvForCall = _ => CKR.CKR_GENERAL_ERROR };

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => new Pkcs11Library(fake));

        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
        Assert.True(fake.DisposeCalled);
    }
}
