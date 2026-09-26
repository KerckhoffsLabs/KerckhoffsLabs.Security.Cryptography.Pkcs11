using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class FipsOnlyPolicyTests
{
    private static readonly ICryptoPolicy Policy = CryptoPolicy.FipsOnly;

    private static bool Allowed(CKM mech, CryptoOperation op)
        => Policy.Evaluate(new MechanismUseRequest(new Mechanism(mech), op)).IsAllowed;

    private static bool Allowed(Mechanism mech, CryptoOperation op)
        => Policy.Evaluate(new MechanismUseRequest(mech, op)).IsAllowed;

    [Fact]
    public void Identity()
    {
        Assert.Equal("FipsOnly", Policy.Name);
        Assert.False(Policy.AllowsOverride);
    }

    [Theory]
    [InlineData(CKM.CKM_AES_GCM, CryptoOperation.Encrypt)]
    [InlineData(CKM.CKM_AES_CBC_PAD, CryptoOperation.Decrypt)]
    [InlineData(CKM.CKM_AES_CTR, CryptoOperation.Encrypt)]
    [InlineData(CKM.CKM_AES_ECB, CryptoOperation.Encrypt)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD, CryptoOperation.Wrap)]
    [InlineData(CKM.CKM_AES_CMAC, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_AES_KEY_GEN, CryptoOperation.GenerateKey)]
    [InlineData(CKM.CKM_SHA_1, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA224, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA3_256, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA_1_HMAC, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SHA256_HMAC, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SHA224_RSA_PKCS_PSS, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_RSA_PKCS, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_ECDSA_SHA256, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_ECDSA, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_EDDSA, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_ECDH1_DERIVE, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_SP800_108_COUNTER_KDF, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_HKDF_DERIVE, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_ML_KEM, CryptoOperation.Encapsulate)]
    [InlineData(CKM.CKM_ML_DSA, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_HASH_ML_DSA_SHA256, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SLH_DSA, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    [InlineData(CKM.CKM_EC_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    [InlineData(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    public void Approved(CKM mech, CryptoOperation op) => Assert.True(Allowed(mech, op));

    [Theory]
    [InlineData(CKM.CKM_DES3_CBC, CryptoOperation.Decrypt, true)]
    [InlineData(CKM.CKM_DES3_CBC, CryptoOperation.Unwrap, true)]
    [InlineData(CKM.CKM_DES3_CBC, CryptoOperation.Encrypt, false)]
    [InlineData(CKM.CKM_DES3_CBC, CryptoOperation.Wrap, false)]
    [InlineData(CKM.CKM_DES3_KEY_GEN, CryptoOperation.GenerateKey, false)]
    [InlineData(CKM.CKM_DES3_CMAC, CryptoOperation.Verify, true)]
    [InlineData(CKM.CKM_DES3_CMAC, CryptoOperation.Sign, false)]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS, CryptoOperation.Verify, true)]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS, CryptoOperation.Sign, false)]
    [InlineData(CKM.CKM_ECDSA_SHA1, CryptoOperation.Verify, true)]
    [InlineData(CKM.CKM_ECDSA_SHA1, CryptoOperation.Sign, false)]
    [InlineData(CKM.CKM_DSA_SHA256, CryptoOperation.Verify, true)]
    [InlineData(CKM.CKM_DSA_SHA256, CryptoOperation.Sign, false)]
    public void LegacyDirections(CKM mech, CryptoOperation op, bool allowed) => Assert.Equal(allowed, Allowed(mech, op));

    // SP 800-131A Rev.2 §6 / Table 5 disallows PKCS#1 v1.5 key transport after 2023 for both the
    // encryption and the decryption of transported keys, and FIPS 140-3 IG D.G grants legacy-use
    // unwrapping only to symmetric (AES / TDEA) key wrapping — so no direction of v1.5 encryption survives.
    [Theory]
    [InlineData(CryptoOperation.Encrypt)]
    [InlineData(CryptoOperation.Decrypt)]
    [InlineData(CryptoOperation.Wrap)]
    [InlineData(CryptoOperation.Unwrap)]
    public void RsaPkcs1v15_Encryption_IsRefusedInEveryDirection(CryptoOperation op)
        => Assert.False(Allowed(CKM.CKM_RSA_PKCS, op));

    // SP 800-131A Rev.2 §7 / Table 6: AES key wrapping only through SP 800-38F methods (KW, KWP, CCM, GCM).
    [Theory]
    [InlineData(CKM.CKM_AES_CBC_PAD, CryptoOperation.Wrap, false)]
    [InlineData(CKM.CKM_AES_CBC_PAD, CryptoOperation.Unwrap, false)]
    [InlineData(CKM.CKM_AES_ECB, CryptoOperation.Unwrap, false)]
    [InlineData(CKM.CKM_AES_CTR, CryptoOperation.Wrap, false)]
    [InlineData(CKM.CKM_AES_XTS, CryptoOperation.Wrap, false)]
    [InlineData(CKM.CKM_AES_XTS, CryptoOperation.Encrypt, true)]
    [InlineData(CKM.CKM_AES_GCM, CryptoOperation.Wrap, true)]
    [InlineData(CKM.CKM_AES_CCM, CryptoOperation.Unwrap, true)]
    [InlineData(CKM.CKM_AES_KEY_WRAP, CryptoOperation.Wrap, true)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD, CryptoOperation.Unwrap, true)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP, CryptoOperation.Wrap, true)]
    public void AesKeyWrapping_OnlyThroughSp80038fMethods(CKM mech, CryptoOperation op, bool allowed)
        => Assert.Equal(allowed, Allowed(mech, op));

    // FIPS 204 §5.4 / FIPS 205 §10: the pre-hash needs at least 128-bit collision strength.
    [Theory]
    [InlineData(CKM.CKM_HASH_ML_DSA, CKM.CKM_SHA256, true)]
    [InlineData(CKM.CKM_HASH_ML_DSA, CKM.CKM_SHA3_512, true)]
    [InlineData(CKM.CKM_HASH_ML_DSA, CKM.CKM_SHA224, false)]
    [InlineData(CKM.CKM_HASH_ML_DSA, CKM.CKM_SHA_1, false)]
    [InlineData(CKM.CKM_HASH_SLH_DSA, CKM.CKM_SHA384, true)]
    [InlineData(CKM.CKM_HASH_SLH_DSA, CKM.CKM_SHA224, false)]
    [InlineData(CKM.CKM_HASH_SLH_DSA, CKM.CKM_MD5, false)]
    public void GenericPqcPreHash_RequiresAStrongHash(CKM mech, CKM hash, bool allowed)
    {
        var m = new Mechanism(mech, new CkmHashPqcSignParams(hash));
        Assert.Equal(allowed, Allowed(m, CryptoOperation.Sign));
        Assert.Equal(allowed, Allowed(m, CryptoOperation.Verify));
    }

    [Theory]
    [InlineData(CKM.CKM_HASH_ML_DSA)]
    [InlineData(CKM.CKM_HASH_SLH_DSA)]
    public void GenericPqcPreHash_WithoutOrWithWrongParameters_IsRefused(CKM mech)
    {
        Assert.False(Allowed(new Mechanism(mech), CryptoOperation.Sign));
        Assert.False(Allowed(new Mechanism(mech, new CkmPqcSignParams()), CryptoOperation.Sign));
    }

    [Theory]
    [InlineData(CKM.CKM_DES_CBC)]
    [InlineData(CKM.CKM_RC4)]
    [InlineData(CKM.CKM_MD5)]
    [InlineData(CKM.CKM_RIPEMD160)]
    [InlineData(CKM.CKM_CHACHA20_POLY1305)]
    [InlineData(CKM.CKM_CHACHA20)]
    [InlineData(CKM.CKM_RSA_X_509)]
    [InlineData(CKM.CKM_RSA_9796)]
    [InlineData(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN)]
    [InlineData(CKM.CKM_XOR_BASE_AND_DATA)]
    [InlineData(CKM.CKM_AES_MAC)]
    [InlineData(CKM.CKM_SHA512_T)]
    [InlineData(CKM.CKM_HASH_ML_DSA_SHA224)]
    [InlineData(CKM.CKM_HASH_ML_DSA_SHA3_224)]
    [InlineData(CKM.CKM_HASH_SLH_DSA_SHA224)]
    [InlineData(CKM.CKM_HASH_SLH_DSA_SHA3_224)]
    public void Refused_ForEveryOperation(CKM mech)
    {
        foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
            Assert.False(Allowed(mech, op), $"{mech} was allowed for {op}");
    }

    [Fact]
    public void VendorAndUnknownMechanisms_AreRefused()
    {
        Assert.False(Allowed(new Mechanism(0x8000_1234UL), CryptoOperation.Encrypt));
        Assert.False(Allowed(new Mechanism(0x7FFF_FFF0UL), CryptoOperation.Encrypt));
    }

    [Fact]
    public void Denials_CiteTheirSource()
    {
        foreach (CKM mech in Enum.GetValues<CKM>())
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
            {
                PolicyDecision d = Policy.Evaluate(new MechanismUseRequest(new Mechanism(mech), op));
                if (!d.IsAllowed)
                    Assert.Matches(@"(SP 800-|FIPS 1|FIPS 2)", d.Reason!);
            }
    }

    [Fact]
    public void Oaep_RequiresAnApprovedHash()
    {
        Mechanism Oaep(CKM h, CKG g) => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(h, g));
        Assert.True(Allowed(Oaep(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256), CryptoOperation.Encrypt));
        // SHA-1 is an approved hash (FIPS 180-4) and acceptable outside signatures (SP 800-131A Rev.2
        // Table 8); SP 800-56B Rev.2 §5.1 / §7.2.2.1 only asks OAEP for an approved hash.
        Assert.True(Allowed(Oaep(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1), CryptoOperation.Wrap));
        Assert.False(Allowed(Oaep(CKM.CKM_MD5, CKG.CKG_MGF1_SHA256), CryptoOperation.Encrypt));
    }

    [Fact]
    public void OaepAndPss_WithoutParameters_AreRefused()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP), CryptoOperation.Encrypt));
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_PSS), CryptoOperation.Sign));
    }

    [Fact]
    public void OaepAndPss_WithTheWrongParameterType_AreRefused()
    {
        var oaepWithPssParams = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
        var pssWithOaepParams = new Mechanism(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

        Assert.False(Allowed(oaepWithPssParams, CryptoOperation.Encrypt));
        Assert.False(Allowed(oaepWithPssParams, CryptoOperation.Decrypt));
        Assert.False(Allowed(pssWithOaepParams, CryptoOperation.Sign));
        Assert.False(Allowed(pssWithOaepParams, CryptoOperation.Verify));
    }

    [Fact]
    public void Pss_Sha1_IsVerifyOnly()
    {
        var pss = new Mechanism(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1, 20));
        Assert.True(Allowed(pss, CryptoOperation.Verify));
        Assert.False(Allowed(pss, CryptoOperation.Sign));
    }

    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS_PSS, 32, true)]
    [InlineData(CKM.CKM_RSA_PKCS_PSS, 33, false)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, 0, true)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, 64, false)]
    public void Pss_SaltLongerThanTheHash_IsRefused(CKM mech, int saltLength, bool allowed)
    {
        var pss = new Mechanism(mech, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength));
        Assert.Equal(allowed, Allowed(pss, CryptoOperation.Sign));
    }

    [Theory]
    [InlineData(1024UL, false)]
    [InlineData(2048UL, true)]
    public void RsaKeyGeneration(ulong bits, bool allowed)
        => Assert.Equal(allowed, Policy.Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, bits)).IsAllowed);

    [Fact]
    public void RsaX931KeyGeneration_IsRefused()
        => Assert.False(Policy.Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, 3072)).IsAllowed);

    [Fact]
    public void EcKeyGeneration_OnlyNistPrimeCurves()
    {
        Assert.True(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP224)).IsAllowed);
        Assert.True(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP384)).IsAllowed);
        Assert.False(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.BrainpoolP256r1)).IsAllowed);
        Assert.False(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.Secp256k1)).IsAllowed);
        Assert.False(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192)).IsAllowed);
    }

    [Fact]
    public void KeyTemplate_NonSensitiveRefused()
    {
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Sensitive(false).Build();
        Assert.False(Policy.Evaluate(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [.. tpl.Attributes])).IsAllowed);
    }

    [Theory]
    [InlineData(CKD.CKD_NULL, false)]
    [InlineData(CKD.CKD_SHA1_KDF, false)]
    [InlineData(CKD.CKD_BLAKE2B_256_KDF, false)]
    [InlineData(CKD.CKD_SHA3_256_KDF, false)]
    [InlineData(CKD.CKD_SHA256_KDF, true)]
    [InlineData(CKD.CKD_SHA3_384_KDF_SP800, true)]
    public void KeyAgreementKdf(CKD kdf, bool allowed)
        => Assert.Equal(allowed, Policy.Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, kdf)).IsAllowed);

    [Theory]
    [InlineData("SHA1", CryptoOperation.Verify, true)]
    [InlineData("SHA1", CryptoOperation.Sign, false)]
    [InlineData("SHA256", CryptoOperation.Sign, true)]
    [InlineData("MD5", CryptoOperation.Verify, false)]
    public void HashUse(string hash, CryptoOperation op, bool allowed)
        => Assert.Equal(allowed, Policy.Evaluate(new HashUseRequest(new HashAlgorithmName(hash), op)).IsAllowed);

    [Theory]
    [InlineData(KeyMaterialExportKind.EcdhSharedSecret)]
    [InlineData(KeyMaterialExportKind.KemSharedSecret)]
    [InlineData(KeyMaterialExportKind.KdfOutput)]
    public void KeyMaterialExport_Refused(KeyMaterialExportKind kind)
        => Assert.False(Policy.Evaluate(new KeyMaterialExportRequest(kind)).IsAllowed);

    // A hash-bound PSS mechanism fixes the message hash, but the MGF/parameter hash it is given must
    // still be approved — otherwise a caller could smuggle MD5 into the MGF of an "approved" mechanism.
    [Theory]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_SHA384_RSA_PKCS_PSS, CryptoOperation.Sign)]
    public void HashedPss_WithAnUnapprovedParameterHash_IsRefused(CKM mech, CryptoOperation op)
    {
        var pss = new Mechanism(mech, new CkmRsaPkcsPssParams(CKM.CKM_MD5, CKG.CKG_MGF1_SHA256, 16));
        PolicyDecision decision = Policy.Evaluate(new MechanismUseRequest(pss, op));
        Assert.False(decision.IsAllowed);
        Assert.Contains("not an approved hash for RSA-PSS", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void HashedPss_WithTheWrongParameterType_IsRefused()
    {
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
        Assert.False(Allowed(pss, CryptoOperation.Sign));
        Assert.False(Allowed(pss, CryptoOperation.Verify));
    }

    [Fact]
    public void HashedPss_WithoutParameters_IsAllowed()
        => Assert.True(Allowed(new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS), CryptoOperation.Sign));

    [Fact]
    public void EcKeyGeneration_OnACurveWithNoOid_IsRefused()
        => Assert.False(Policy.Evaluate(new EcKeyGenerationRequest(default)).IsAllowed);
}
