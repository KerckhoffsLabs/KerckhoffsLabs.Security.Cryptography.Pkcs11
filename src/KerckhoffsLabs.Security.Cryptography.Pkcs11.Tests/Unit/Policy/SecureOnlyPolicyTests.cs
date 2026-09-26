using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009, KLPKCS11010 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class SecureOnlyPolicyTests
{
    private static readonly ICryptoPolicy Policy = CryptoPolicy.SecureOnly;

    private static bool Allowed(PolicyRequest r) => Policy.Evaluate(r).IsAllowed;

    [Fact]
    public void Identity()
    {
        Assert.Equal("SecureOnly", Policy.Name);
        Assert.True(Policy.AllowsOverride);
    }

    [Fact]
    public void MechanismVerdict_IsTheSameForEveryOperation()
    {
        foreach (CKM mech in Enum.GetValues<CKM>())
        {
            bool first = Allowed(new MechanismUseRequest(new Mechanism(mech), CryptoOperation.Encrypt));
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
                Assert.Equal(first, Allowed(new MechanismUseRequest(new Mechanism(mech), op)));
        }
    }

    [Fact]
    public void OaepHashParameter_IsInspected()
    {
        Assert.False(Allowed(new MechanismUseRequest(
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)), CryptoOperation.Encrypt)));
        Assert.False(Allowed(new MechanismUseRequest(
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224)), CryptoOperation.Encrypt)));
        Assert.True(Allowed(new MechanismUseRequest(
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.Encrypt)));
    }

    [Fact]
    public void VendorMechanism_IsAllowed()
        => Assert.True(Allowed(new MechanismUseRequest(new Mechanism(0x8000_1234UL), CryptoOperation.Sign)));

    [Theory]
    [InlineData(1024UL, false)]
    [InlineData(2047UL, false)]
    [InlineData(2048UL, true)]
    [InlineData(4096UL, true)]
    public void RsaKeyGeneration_Floor(ulong bits, bool allowed)
    {
        Assert.Equal(allowed, Allowed(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, bits)));
        Assert.Equal(allowed, Allowed(new RsaKeyGenerationRequest(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, bits)));
    }

    [Fact]
    public void EcKeyGeneration_BelowBaselineCurveRefused()
    {
        Assert.False(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP224)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.BrainpoolP256r1)));
    }

    [Fact]
    public void KeyTemplate_NonSensitiveRefused_ExtractableAllowed()
    {
        using var nonSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        Assert.False(Allowed(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [nonSensitive])));
        Assert.True(Allowed(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [extractable])));
        Assert.True(Allowed(new KeyTemplateRequest(null, [])));
    }

    [Fact]
    public void KeyAgreementKdf_NullRefused()
    {
        Assert.False(Allowed(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));
        Assert.True(Allowed(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA256_KDF)));
    }

    [Fact]
    public void HashUse_Sha1Refused_InBothDirections()
    {
        Assert.False(Allowed(new HashUseRequest(HashAlgorithmName.SHA1, CryptoOperation.Sign)));
        Assert.False(Allowed(new HashUseRequest(HashAlgorithmName.SHA1, CryptoOperation.Verify)));
        Assert.True(Allowed(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)));
    }

    [Theory]
    [InlineData(KeyMaterialExportKind.EcdhSharedSecret)]
    [InlineData(KeyMaterialExportKind.KemSharedSecret)]
    [InlineData(KeyMaterialExportKind.KdfOutput)]
    public void KeyMaterialExport_Refused(KeyMaterialExportKind kind)
        => Assert.False(Allowed(new KeyMaterialExportRequest(kind)));

    [Fact]
    public void Denials_DoNotMentionTheRemovedOptIn()
    {
        foreach (CKM mech in Enum.GetValues<CKM>())
        {
            PolicyDecision d = Policy.Evaluate(new MechanismUseRequest(new Mechanism(mech), CryptoOperation.Encrypt));
            if (!d.IsAllowed)
                Assert.DoesNotContain("AllowInsecure", d.Reason, StringComparison.Ordinal);
        }
    }

    // The RSA size floor judges RSA key-pair generation only; a request naming another mechanism is not
    // this rule's business and must not be refused by it.
    [Fact]
    public void RsaKeyGeneration_ForANonRsaMechanism_IsNotJudgedOnSize()
        => Assert.True(Allowed(new RsaKeyGenerationRequest(CKM.CKM_EC_KEY_PAIR_GEN, 512)));
}
