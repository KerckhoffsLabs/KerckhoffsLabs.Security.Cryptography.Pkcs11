using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A failed <c>C_GenerateKeyPair</c> reaches the token once and its code reaches the caller. A token may refuse a
/// pair and still keep the half it made first (SoftHSM2 does, see <c>ObjectConformanceTests.SoftHsm2</c>), so a
/// silent retry could leave one orphan per attempt; whether to retry, and what to clean up first, is the caller's call.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GenerateKeyPairFailureTests
{
    private sealed class FailingFake(CKR rv) : SessionTestModule
    {
        public int GenerateCalls { get; private set; }

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            GenerateCalls++;
            return rv;
        }
    }

    [Theory]
    [InlineData(CKR.CKR_FUNCTION_FAILED)]
    [InlineData(CKR.CKR_GENERAL_ERROR)]
    [InlineData(CKR.CKR_DEVICE_ERROR)]
    public void FailedGeneration_ReachesTheTokenOnce_AndSurfacesItsCode(CKR rv)
    {
        using var fake = new FailingFake(rv);
        using var session = fake.CreateSession(sessionId: 1);
        using var publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label("pair").Verify().EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Build();
        using var privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label("pair").Sign().Build();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [.. publicTemplate.Attributes], [.. privateTemplate.Attributes], out _, out _));

        Assert.Equal(rv, ex.ReturnValue);
        Assert.Equal(1, fake.GenerateCalls);
    }

    /// <summary>
    /// The spec leaves <c>phPublicKey</c>/<c>phPrivateKey</c> unspecified when the call fails, and a module may have
    /// written them anyway. Whatever they hold names nothing the caller asked for (or, after a handle is reused,
    /// names someone else's object), so the façade neither destroys them nor hands them back as a key.
    /// </summary>
    private sealed class HandlesWrittenModule : FakeModule
    {
        public int DestroyCalls { get; private set; }

        protected override bool ReleasedByFinalize => true;

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            publicKey = (NativeCULong)41UL;
            privateKey = (NativeCULong)42UL;
            return CKR.CKR_FUNCTION_FAILED;
        }

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        {
            DestroyCalls++;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void FailedGeneration_WithHandlesWritten_NeitherDestroysNorWrapsThem()
    {
        using var module = new HandlesWrittenModule();
        using Pkcs11Library library = module.Load();
        LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1);
        using var session = new Pkcs11Session(library, new Pkcs11Slot(library, slotId: 1), core);
        using var publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label("pair").Verify().EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Build();
        using var privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label("pair").Sign().Build();
        Pkcs11Key? key = null;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate));

        Assert.Equal(CKR.CKR_FUNCTION_FAILED, ex.ReturnValue);
        Assert.Null(key);
        Assert.Equal(0, module.DestroyCalls);
    }
}
