using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable KLPKCS11007 // weak curves are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The EC curve is judged on every key-pair generation, not only through
/// <see cref="Pkcs11Workspace.GenerateEcKeyPair"/>: the generic <c>GenerateKeyPair(mechanism, public, private)</c>
/// path reaches the same session call and must meet the same curve allow-list.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class EcKeyGenCurveGateTests
{
    private sealed class RecordingFake : SessionTestModule
    {
        public new int Calls { get; private set; }

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            Calls++;
            publicKey = (NativeCULong)10UL;
            privateKey = (NativeCULong)11UL;
            return CKR.CKR_OK;
        }
    }

    private static void GenerateEc(Pkcs11Session session, byte[]? ecParams)
    {
        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Verify();
        if (ecParams is not null)
            pub = pub.EcParams(ecParams);
        using var pubTpl = pub.Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign().Build();
        session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [.. pubTpl.Attributes], [.. privTpl.Attributes], out _, out _);
    }

    // CKM_ECDSA_KEY_PAIR_GEN is the same value as CKM_EC_KEY_PAIR_GEN, so this covers both spellings.
    [Fact]
    public void WeakCurve_IsRefusedBeforeReachingTheToken()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1);

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => GenerateEc(session, Pkcs11ECCurve.NamedCurves.NistP192.GetEcParams()));
        Assert.IsType<EcKeyGenerationRequest>(ex.Request);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void AllowedCurve_Proceeds()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1);

        GenerateEc(session, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams());
        Assert.Equal(1, fake.Calls);
    }

    [Fact]
    public void TheCurveVerdictFollowsThePolicy()
    {
        byte[] brainpool = Pkcs11ECCurve.NamedCurves.BrainpoolP256r1.GetEcParams();

        using (var secure = new RecordingFake())
        {
            using (var session = secure.CreateSession(sessionId: 1))
                GenerateEc(session, brainpool);
            Assert.Equal(1, secure.Calls);
        }

        using var fips = new RecordingFake();
        using (var session = fips.CreateSession(sessionId: 1, policy: CryptoPolicy.FipsOnly))
            Assert.Throws<CryptoPolicyViolationException>(() => GenerateEc(session, brainpool));
        Assert.Equal(0, fips.Calls);
    }

    // Explicit curve parameters (or any CKA_EC_PARAMS that is not a named-curve OID) name no curve on
    // any allow-list, so the restrictive policies refuse them; AllowInsecure still lets them through.
    [Fact]
    public void EcParamsThatAreNotANamedCurveOid_AreRefusedUnlessInsecureIsAllowed()
    {
        byte[] printableCurveName = [0x13, 0x0A, .. "prime256v1"u8];

        using (var secure = new RecordingFake())
        {
            using (var session = secure.CreateSession(sessionId: 1))
                Assert.Throws<CryptoPolicyViolationException>(() => GenerateEc(session, printableCurveName));
            Assert.Equal(0, secure.Calls);
        }

        using var insecure = new RecordingFake();
        using (var session = insecure.CreateSession(sessionId: 1, policy: CryptoPolicy.AllowInsecure))
            GenerateEc(session, printableCurveName);
        Assert.Equal(1, insecure.Calls);
    }

    // With no CKA_EC_PARAMS there is no curve to judge; the token rejects the incomplete template itself.
    [Fact]
    public void NoEcParams_LeavesTheTemplateToTheToken()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1);

        GenerateEc(session, ecParams: null);
        Assert.Equal(1, fake.Calls);
    }

    // The public generic path: before this check it generated a P-224 key the curve allow-list refuses.
    [Fact]
    public void Workspace_GenericGenerateKey_RefusesAWeakCurve()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC).EcParams(Pkcs11ECCurve.NamedCurves.NistP224.GetEcParams()).Verify().Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign().Build();

        Assert.Throws<CryptoPolicyViolationException>(
            () => workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl));
    }
}
