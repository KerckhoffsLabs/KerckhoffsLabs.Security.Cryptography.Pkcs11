using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class MechanismChecksTests
{
    private static readonly PolicyCatalogue Owner = new()
    {
        AllowedMechanisms = FrozenDictionary<CKM, MechanismRule>.Empty,
        AllowedVendorMechanisms = FrozenDictionary<ulong, MechanismRule>.Empty,
        AllowedHashes = FrozenDictionary<string, AllowedHash>.Empty,
        AllowedCurves = FrozenDictionary<string, string>.Empty,
        AllowedKdfs = FrozenDictionary<CKD, string>.Empty,
        AllowedKeyAgreementKeyTypes = FrozenDictionary<CKK, string>.Empty,
        AllowedKdfPrfs = FrozenDictionary<string, FrozenSet<string>>.Empty,
        RsaKeyGeneration = RsaKeyGenerationRule.Minimum(2048),
        KeyTemplate = KeyTemplateRule.RequireSensitive(),
        SecretExport = SecretExportRule.Refuse(),
        DocumentedRefusedMechanisms = FrozenDictionary<CKM, DocumentedRefusal>.Empty,
        DocumentedRefusedHashes = FrozenDictionary<string, DocumentedRefusal>.Empty,
        DocumentedRefusedCurves = FrozenDictionary<string, DocumentedRefusal>.Empty,
        DocumentedRefusedKdfs = FrozenDictionary<CKD, DocumentedRefusal>.Empty,
        DocumentedRefusedKeyAgreementKeyTypes = FrozenDictionary<CKK, DocumentedRefusal>.Empty,
        DocumentedRefusedPrfs = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["CKM_SHA_1_HMAC"] = new("SHA-1 is collision-broken.", "CKM_SHA256_HMAC"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
    };

    private static PolicyDecision Run(MechanismCheck check, Mechanism m, CryptoOperation op = CryptoOperation.Encrypt)
        => check.Evaluate(m, op, Owner);

    [Fact]
    public void OaepHash_AllowsOnlyTheGivenHashes_AndNamesThemWhenItDenies()
    {
        MechanismCheck check = MechanismChecks.OaepHash([CKM.CKM_SHA384, CKM.CKM_SHA256]);
        Assert.True(Run(check, new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256))).IsAllowed);
        PolicyDecision d = Run(check, new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)));
        Assert.Equal("CKM_SHA_1 is not an allowed OAEP hash; allowed: CKM_SHA256, CKM_SHA384.", d.Reason);
        Assert.Equal("CKM_RSA_PKCS_OAEP requires CkmRsaPkcsOaepParams naming CKM_SHA256, CKM_SHA384.",
            Run(check, new Mechanism(CKM.CKM_RSA_PKCS_OAEP)).Reason);
        Assert.Equal("requires CkmRsaPkcsOaepParams naming CKM_SHA256, CKM_SHA384", check.Description);
    }

    [Fact]
    public void RsaPss_ChecksHashSaltAndVerifyOnlyHashes()
    {
        MechanismCheck raw = MechanismChecks.RsaPss([CKM.CKM_SHA256], parametersRequired: true, verifyOnlyHashes: [CKM.CKM_SHA_1]);
        Mechanism Pss(CKM h, int salt) => new(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(h, CKG.CKG_MGF1_SHA256, salt));
        Assert.True(Run(raw, Pss(CKM.CKM_SHA256, 32), CryptoOperation.Sign).IsAllowed);
        Assert.Equal("A 33-byte RSA-PSS salt exceeds the 32-byte CKM_SHA256 output.", Run(raw, Pss(CKM.CKM_SHA256, 33), CryptoOperation.Sign).Reason);
        Assert.True(Run(raw, Pss(CKM.CKM_SHA_1, 20), CryptoOperation.Verify).IsAllowed);
        Assert.Equal("CKM_SHA_1 is allowed for RSA-PSS only to Verify, not to Sign.", Run(raw, Pss(CKM.CKM_SHA_1, 20), CryptoOperation.Sign).Reason);
        Assert.Equal("CKM_SHA384 is not an allowed RSA-PSS hash; allowed: CKM_SHA256.", Run(raw, Pss(CKM.CKM_SHA384, 48), CryptoOperation.Sign).Reason);
        Assert.False(Run(raw, new Mechanism(CKM.CKM_RSA_PKCS_PSS), CryptoOperation.Sign).IsAllowed);

        MechanismCheck hashed = MechanismChecks.RsaPss([CKM.CKM_SHA256], parametersRequired: false);
        Assert.True(Run(hashed, new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS), CryptoOperation.Sign).IsAllowed);
        Assert.False(Run(hashed, new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.Sign).IsAllowed);
    }

    [Fact]
    public void RsaPss_RejectsAHashWithoutAKnownOutputLength() =>
        Assert.Throws<ArgumentException>(() => MechanismChecks.RsaPss([CKM.CKM_MD5_HMAC], parametersRequired: true));

    [Fact]
    public void PqcPreHash_AllowsOnlyTheGivenPreHashes()
    {
        MechanismCheck check = MechanismChecks.PqcPreHash([CKM.CKM_SHA384]);
        Assert.True(Run(check, new Mechanism(CKM.CKM_HASH_ML_DSA, new CkmHashPqcSignParams(CKM.CKM_SHA384)), CryptoOperation.Sign).IsAllowed);
        Assert.Equal("HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams naming CKM_SHA384.",
            Run(check, new Mechanism(CKM.CKM_HASH_ML_DSA, new CkmHashPqcSignParams(CKM.CKM_SHA256)), CryptoOperation.Sign).Reason);
    }

    [Theory]
    [InlineData(96, true)]
    [InlineData(88, false)]
    public void GcmTagLength_AppliesItsFloorToBothParameterTypes(int bits, bool allowed)
    {
        MechanismCheck check = MechanismChecks.GcmTagLength(96);
        Assert.Equal(allowed, Run(check, new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], default, bits))).IsAllowed);
        Assert.Equal(allowed, Run(check, new Mechanism(CKM.CKM_AES_GCM, CkmGcmMessageParams.ForEncrypt(new byte[12], bits / 8))).IsAllowed);
        if (!allowed)
            Assert.Equal($"A {bits}-bit AES-GCM tag is below this policy's 96-bit minimum.",
                Run(check, new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], default, bits))).Reason);
    }

    [Fact]
    public void AeadTagChecks_AllowNoParameters_RefuseRawBytes()
    {
        Assert.True(Run(MechanismChecks.GcmTagLength(96), new Mechanism(CKM.CKM_AES_GCM)).IsAllowed);
        Assert.False(Run(MechanismChecks.GcmTagLength(96), new Mechanism(CKM.CKM_AES_GCM, new byte[40])).IsAllowed);
        Assert.False(Run(MechanismChecks.CcmMacLength(64), new Mechanism(CKM.CKM_AES_CCM, new byte[40])).IsAllowed);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(8, true)]
    public void CcmMacLength_AppliesItsFloorToBothParameterTypes(int bytes, bool allowed)
    {
        MechanismCheck check = MechanismChecks.CcmMacLength(64);
        Assert.Equal(allowed, Run(check, new Mechanism(CKM.CKM_AES_CCM, new CkmAesCcmParams(16, new byte[12], default, bytes))).IsAllowed);
        Assert.Equal(allowed, Run(check, new Mechanism(CKM.CKM_AES_CCM, CkmCcmMessageParams.ForEncrypt(16, new byte[12], bytes))).IsAllowed);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(129)]
    public void AeadFloors_OutsideTheSpecRange_Throw(int bits)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => MechanismChecks.GcmTagLength(bits));
        Assert.Throws<ArgumentOutOfRangeException>(() => MechanismChecks.CcmMacLength(bits));
    }

    [Fact]
    public void KdfPrf_UsesTheOwnersDocumentedRefusal()
    {
        MechanismCheck check = MechanismChecks.Sp800108Prf([CKM.CKM_SHA256_HMAC]);
        Mechanism Kdf(CKM prf) => new(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.Counter(prf).IterationCounter().Build());
        Assert.True(Run(check, Kdf(CKM.CKM_SHA256_HMAC), CryptoOperation.Derive).IsAllowed);
        Assert.Equal("CKM_SHA_1_HMAC is not allowed as a SP 800-108 PRF: SHA-1 is collision-broken. Use CKM_SHA256_HMAC.",
            Run(check, Kdf(CKM.CKM_SHA_1_HMAC), CryptoOperation.Derive).Reason);
        Assert.Equal("CKM_SHA384_HMAC is not an allowed SP 800-108 PRF; allowed: CKM_SHA256_HMAC.",
            Run(check, Kdf(CKM.CKM_SHA384_HMAC), CryptoOperation.Derive).Reason);
    }

    [Fact]
    public void Pbkdf2AndHkdfPrf_AllowOnlyTheGivenPrfs()
    {
        Assert.True(Run(MechanismChecks.Pbkdf2Prf([CKP.CKP_PKCS5_PBKD2_HMAC_SHA256]),
            new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params([1], 1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, [1])), CryptoOperation.Derive).IsAllowed);
        Assert.False(Run(MechanismChecks.HkdfPrf([CKM.CKM_SHA256]),
            new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA384)), CryptoOperation.Derive).IsAllowed);
    }

    [Fact]
    public void EmptyAllowedSets_Throw()
    {
        Assert.Throws<ArgumentException>(() => MechanismChecks.OaepHash([]));
        Assert.Throws<ArgumentException>(() => MechanismChecks.HkdfPrf([]));
    }

    // Raw parameter bytes are parameters "given" but unreadable: a hash-bound PSS check must not wave them
    // through, or the hash and salt checks it documents are skipped.
    [Fact]
    public void RsaPss_HashBound_RefusesRawParameterBytes()
    {
        MechanismCheck hashed = MechanismChecks.RsaPss([CKM.CKM_SHA256], parametersRequired: false);
        Assert.False(Run(hashed, new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new byte[24]), CryptoOperation.Sign).IsAllowed);
        Assert.True(Run(hashed, new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS), CryptoOperation.Sign).IsAllowed);
    }

    [Fact]
    public void Checks_HaveValueEquality()
    {
        Assert.Equal(MechanismChecks.GcmTagLength(96), MechanismChecks.GcmTagLength(96));
        Assert.Equal(MechanismChecks.GcmTagLength(96).GetHashCode(), MechanismChecks.GcmTagLength(96).GetHashCode());
        Assert.NotEqual(MechanismChecks.GcmTagLength(96), MechanismChecks.GcmTagLength(104));
        Assert.NotEqual<MechanismCheck>(MechanismChecks.GcmTagLength(64), MechanismChecks.CcmMacLength(64));
        Assert.Equal(MechanismChecks.OaepHash([CKM.CKM_SHA256, CKM.CKM_SHA384]), MechanismChecks.OaepHash([CKM.CKM_SHA384, CKM.CKM_SHA256]));
        Assert.Equal(MechanismChecks.HkdfPrf([CKM.CKM_SHA256]), MechanismChecks.HkdfPrf([CKM.CKM_SHA256]));
        Assert.NotEqual(MechanismChecks.RsaPss([CKM.CKM_SHA256], true), MechanismChecks.RsaPss([CKM.CKM_SHA256], false));
    }

    [Fact]
    public void RsaPss_EmptyVerifyOnlyHashes_Throw() =>
        Assert.Throws<ArgumentException>(() => MechanismChecks.RsaPss([CKM.CKM_SHA256], parametersRequired: true, verifyOnlyHashes: []));

    [Fact]
    public void Descriptions_NameTheirFloorOrSet()
    {
        Assert.Equal("MAC, when parameters are given, of at least 64 bits", MechanismChecks.CcmMacLength(64).Description);
        Assert.Equal("requires CkmPkcs5Pbkd2Params naming CKP_PKCS5_PBKD2_HMAC_SHA256", MechanismChecks.Pbkdf2Prf([CKP.CKP_PKCS5_PBKD2_HMAC_SHA256]).Description);
        Assert.Equal("requires CkmSp800108KdfParams naming CKM_AES_CMAC, CKM_SHA256_HMAC",
            MechanismChecks.Sp800108Prf([CKM.CKM_SHA256_HMAC, CKM.CKM_AES_CMAC]).Description);
        Assert.Equal("requires CkmHkdfParams naming CKM_SHA256", MechanismChecks.HkdfPrf([CKM.CKM_SHA256]).Description);
    }

    [Fact]
    public void NullSets_ThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.OaepHash(null!));
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.RsaPss(null!, parametersRequired: true));
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.PqcPreHash(null!));
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.Pbkdf2Prf(null!));
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.Sp800108Prf(null!));
        Assert.Throws<ArgumentNullException>(() => MechanismChecks.HkdfPrf(null!));
    }
}
