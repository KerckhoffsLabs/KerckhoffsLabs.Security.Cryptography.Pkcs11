using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class Cnsa20PolicyTests
{
    private static readonly ComposedCryptoPolicy Policy = CryptoPolicy.Cnsa20;

    private static PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation)
        => Policy.Evaluate(new MechanismUseRequest(mechanism, operation));

    private static PolicyDecision Strength(CKK? type, int? length = null, ulong? set = null, ulong? levels = null)
        => Policy.Evaluate(new KeyStrengthRequest(type, KeyStrengthSource.ExistingKey)
        {
            ValueLengthBytes = length,
            ParameterSet = set,
            HssLevels = levels,
        });

    [Fact]
    public void Cnsa20_InspectsKeys_AndRefusesOverride()
    {
        Assert.Equal("Cnsa20", Policy.Name);
        Assert.True(Policy.InspectsKeys);
        Assert.False(Policy.AllowsOverride);
    }

    [Fact]
    public void Cnsa20_RefusesOverride()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.Cnsa20);
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
    }

    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS_PSS)]
    [InlineData(CKM.CKM_ECDSA)]
    [InlineData(CKM.CKM_ECDH1_DERIVE)]
    [InlineData(CKM.CKM_SLH_DSA)]
    [InlineData(CKM.CKM_HASH_ML_DSA)]
    [InlineData(CKM.CKM_XMSSMT)]
    [InlineData(CKM.CKM_CHACHA20_POLY1305)]
    [InlineData(CKM.CKM_AES_CBC)]
    [InlineData(CKM.CKM_SHA256)]
    public void Cnsa20_RefusesNonCnsaMechanisms(CKM mechanism)
    {
        DocumentedRefusal refusal = Policy.Catalogue.DocumentedRefusedMechanisms[mechanism];
        foreach (CryptoOperation operation in Enum.GetValues<CryptoOperation>())
        {
            PolicyDecision d = Evaluate(RecommendedPolicyTests.ValidMechanismFor(mechanism), operation);
            Assert.False(d.IsAllowed, $"{mechanism} {operation}");
            Assert.Contains(refusal.Reason, d.Reason, StringComparison.Ordinal);
            Assert.DoesNotContain("not reviewed", d.Reason, StringComparison.Ordinal);
        }
    }

    // Golden list: Cnsa20's allowed mechanisms and their exact operations.
    [Fact]
    public void Cnsa20_AllowsExactlyTheCnsaMechanisms()
    {
        const CryptoOperations cipher = CryptoOperations.Encrypt | CryptoOperations.Decrypt | CryptoOperations.Wrap | CryptoOperations.Unwrap;
        const CryptoOperations signature = CryptoOperations.Sign | CryptoOperations.Verify;
        var expected = new Dictionary<CKM, CryptoOperations>();
        void Add(CryptoOperations ops, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) expected.Add(m, ops);
        }

        Add(cipher, CKM.CKM_AES_GCM, CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP);
        Add(CryptoOperations.GenerateKey, CKM.CKM_AES_KEY_GEN, CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA384_KEY_GEN,
            CKM.CKM_SHA512_KEY_GEN, CKM.CKM_HKDF_KEY_GEN);
        Add(CryptoOperations.Digest, CKM.CKM_SHA384, CKM.CKM_SHA512);
        Add(signature, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL);
        Add(CryptoOperations.Derive, CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF,
            CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF, CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA);
        Add(CryptoOperations.Encapsulate | CryptoOperations.Decapsulate, CKM.CKM_ML_KEM);
        Add(CryptoOperations.GenerateKeyPair, CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN,
            CKM.CKM_HSS_KEY_PAIR_GEN, CKM.CKM_XMSS_KEY_PAIR_GEN);
        Add(signature, CKM.CKM_ML_DSA, CKM.CKM_HSS, CKM.CKM_XMSS);

        Assert.Equal(
            expected.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}: {kv.Value}"),
            Policy.Catalogue.AllowedMechanisms.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}: {kv.Value.Operations}"));
        Assert.All(Policy.Catalogue.AllowedMechanisms.Values, r => Assert.Equal(CryptoOperations.None, r.LegacyOperations));
        Assert.Empty(Policy.Catalogue.AllowedVendorMechanisms);
    }

    // A developer moving from either built-in learns why each mechanism it allowed is refused here.
    [Fact]
    public void EveryMechanismAnotherBuiltInAllows_IsAllowedOrDocumentedAsRefused()
    {
        IEnumerable<CKM> others = CryptoPolicy.Recommended.Catalogue.AllowedMechanisms.Keys
            .Concat(CryptoPolicy.NistApproved.Catalogue.AllowedMechanisms.Keys);
        CKM[] missing = others.Distinct()
            .Where(m => !Policy.Catalogue.AllowedMechanisms.ContainsKey(m) && !Policy.Catalogue.DocumentedRefusedMechanisms.ContainsKey(m))
            .Order().ToArray();
        Assert.Empty(missing);
    }

    [Fact]
    public void EveryHashCurveKdfAndKeyTypeAnotherBuiltInAllows_IsDocumentedAsRefused()
    {
        PolicyCatalogue c = Policy.Catalogue;
        PolicyCatalogue[] others = [CryptoPolicy.Recommended.Catalogue, CryptoPolicy.NistApproved.Catalogue];
        string[] hashes = [.. others.SelectMany(o => o.AllowedHashes.Keys).Distinct()
            .Where(h => !c.AllowedHashes.ContainsKey(h) && !c.DocumentedRefusedHashes.ContainsKey(h))];
        string[] curves = [.. others.SelectMany(o => o.AllowedCurves.Keys).Distinct().Where(o => !c.DocumentedRefusedCurves.ContainsKey(o))];
        CKD[] kdfs = [.. others.SelectMany(o => o.AllowedKdfs.Keys).Distinct().Where(k => !c.DocumentedRefusedKdfs.ContainsKey(k))];
        CKK[] keyTypes = [.. others.SelectMany(o => o.AllowedKeyAgreementKeyTypes.Keys).Distinct()
            .Where(k => !c.DocumentedRefusedKeyAgreementKeyTypes.ContainsKey(k))];
        Assert.Empty(hashes);
        Assert.Empty(curves);
        Assert.Empty(kdfs);
        Assert.Empty(keyTypes);
    }

    [Fact]
    public void Cnsa20_AllowsOnlySha384AndSha512_AndNoCurveKdfOrKeyAgreementKeyType()
    {
        PolicyCatalogue c = Policy.Catalogue;
        Assert.Equal(["SHA384", "SHA512"], c.AllowedHashes.Keys.Order(StringComparer.Ordinal));
        Assert.Empty(c.AllowedCurves);
        Assert.Empty(c.AllowedKdfs);
        Assert.Empty(c.AllowedKeyAgreementKeyTypes);
        Assert.True(Policy.Evaluate(new HashUseRequest(HashAlgorithmName.SHA384, CryptoOperation.Sign)).IsAllowed);
        Assert.False(Policy.Evaluate(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)).IsAllowed);
        Assert.False(Policy.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP384)).IsAllowed);
    }

    [Fact]
    public void Cnsa20_AllowsGcmWith128BitTag_RefusesShorter()
    {
        Assert.True(Evaluate(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128)), CryptoOperation.Encrypt).IsAllowed);
        Assert.True(Evaluate(new Mechanism(CKM.CKM_AES_GCM, CkmGcmMessageParams.ForEncrypt(new byte[12], 16)), CryptoOperation.Encrypt).IsAllowed);

        PolicyDecision d = Evaluate(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 96)), CryptoOperation.Encrypt);
        Assert.False(d.IsAllowed);
        Assert.Equal("CNSA 2.0 (this policy): a 96-bit AES-GCM tag is refused; use a 128-bit tag.", d.Reason);
        Assert.False(Evaluate(new Mechanism(CKM.CKM_AES_GCM, CkmGcmMessageParams.ForEncrypt(new byte[12], 12)), CryptoOperation.Encrypt).IsAllowed);
    }

    [Fact]
    public void Cnsa20_Sp800108_AllowsOnlyHmacSha384And512()
    {
        foreach (CKM kdf in new[] { CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF })
        {
            foreach (CKM prf in new[] { CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC })
                Assert.True(Evaluate(new Mechanism(kdf, CkmSp800108KdfParams.CounterModeHmac(prf, "l"u8, "c"u8)), CryptoOperation.Derive).IsAllowed,
                    $"{kdf} {prf}");
            foreach (CKM prf in new[] { CKM.CKM_SHA256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_AES_CMAC, CKM.CKM_SHA_1_HMAC })
            {
                PolicyDecision d = Evaluate(new Mechanism(kdf, CkmSp800108KdfParams.CounterModeHmac(prf, "l"u8, "c"u8)), CryptoOperation.Derive);
                Assert.False(d.IsAllowed, $"{kdf} {prf}");
                Assert.Contains("CNSA 2.0", d.Reason, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Cnsa20_Hkdf_AllowsOnlySha384And512_InHashOrHmacForm()
    {
        foreach (CKM mechanism in new[] { CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA })
        {
            foreach (CKM prf in new[] { CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC })
                Assert.True(Evaluate(new Mechanism(mechanism, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, prf)), CryptoOperation.Derive).IsAllowed,
                    $"{mechanism} {prf}");
            foreach (CKM prf in new[] { CKM.CKM_SHA256, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA3_512, CKM.CKM_SHA_1 })
                Assert.False(Evaluate(new Mechanism(mechanism, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, prf)), CryptoOperation.Derive).IsAllowed,
                    $"{mechanism} {prf}");
        }
    }

    private const ulong MlKem512 = (ulong)CkpMlKem.CKP_ML_KEM_512;
    private const ulong MlKem768 = (ulong)CkpMlKem.CKP_ML_KEM_768;
    private const ulong MlKem1024 = (ulong)CkpMlKem.CKP_ML_KEM_1024;
    private const ulong MlDsa44 = (ulong)CkpMlDsa.CKP_ML_DSA_44;
    private const ulong MlDsa65 = (ulong)CkpMlDsa.CKP_ML_DSA_65;
    private const ulong MlDsa87 = (ulong)CkpMlDsa.CKP_ML_DSA_87;

    [Theory]
    // AES: exactly 256 bits.
    [InlineData(CKK.CKK_AES, 32, null, null, true, null)]
    [InlineData(CKK.CKK_AES, 16, null, null, false, "CNSA 2.0 requires AES-256; this is AES-128.")]
    [InlineData(CKK.CKK_AES, 24, null, null, false, "CNSA 2.0 requires AES-256; this is AES-192.")]
    [InlineData(CKK.CKK_AES, null, null, null, false, "The token did not report the key's length, so CNSA 2.0 compliance can't be verified.")]
    // Secrets: at least 256 bits.
    [InlineData(CKK.CKK_GENERIC_SECRET, 32, null, null, true, null)]
    [InlineData(CKK.CKK_GENERIC_SECRET, 64, null, null, true, null)]
    [InlineData(CKK.CKK_GENERIC_SECRET, 16, null, null, false, "CNSA 2.0 requires a secret of at least 256 bits; this is 128 bits.")]
    [InlineData(CKK.CKK_GENERIC_SECRET, null, null, null, false, "The token did not report the key's length, so CNSA 2.0 compliance can't be verified.")]
    [InlineData(CKK.CKK_HKDF, 48, null, null, true, null)]
    [InlineData(CKK.CKK_HKDF, 31, null, null, false, "CNSA 2.0 requires a secret of at least 256 bits; this is 248 bits.")]
    [InlineData(CKK.CKK_SHA384_HMAC, 48, null, null, true, null)]
    [InlineData(CKK.CKK_SHA384_HMAC, 16, null, null, false, "CNSA 2.0 requires a secret of at least 256 bits; this is 128 bits.")]
    [InlineData(CKK.CKK_SHA512_HMAC, 64, null, null, true, null)]
    [InlineData(CKK.CKK_SHA512_HMAC, null, null, null, false, "The token did not report the key's length, so CNSA 2.0 compliance can't be verified.")]
    // ML-KEM: 1024 only.
    [InlineData(CKK.CKK_ML_KEM, null, MlKem1024, null, true, null)]
    [InlineData(CKK.CKK_ML_KEM, null, MlKem768, null, false, "CNSA 2.0 requires ML-KEM-1024; this is CKP_ML_KEM_768.")]
    [InlineData(CKK.CKK_ML_KEM, null, MlKem512, null, false, "CNSA 2.0 requires ML-KEM-1024; this is CKP_ML_KEM_512.")]
    [InlineData(CKK.CKK_ML_KEM, null, 0x99UL, null, false, "CNSA 2.0 requires ML-KEM-1024; this is 0x99.")]
    [InlineData(CKK.CKK_ML_KEM, null, null, null, false, "The token did not report the key's parameter set, so CNSA 2.0 compliance can't be verified.")]
    // ML-DSA: 87 only.
    [InlineData(CKK.CKK_ML_DSA, null, MlDsa87, null, true, null)]
    [InlineData(CKK.CKK_ML_DSA, null, MlDsa65, null, false, "CNSA 2.0 requires ML-DSA-87; this is CKP_ML_DSA_65.")]
    [InlineData(CKK.CKK_ML_DSA, null, MlDsa44, null, false, "CNSA 2.0 requires ML-DSA-87; this is CKP_ML_DSA_44.")]
    [InlineData(CKK.CKK_ML_DSA, null, null, null, false, "The token did not report the key's parameter set, so CNSA 2.0 compliance can't be verified.")]
    // HSS: single level.
    [InlineData(CKK.CKK_HSS, null, null, 1UL, true, null)]
    [InlineData(CKK.CKK_HSS, null, null, 2UL, false, "CNSA 2.0 requires single-level LMS (HSS levels = 1); this is 2 levels.")]
    [InlineData(CKK.CKK_HSS, null, null, null, false, "The token did not report the key's HSS levels, so CNSA 2.0 compliance can't be verified.")]
    // XMSS: always.
    [InlineData(CKK.CKK_XMSS, null, null, null, true, null)]
    // Everything else.
    [InlineData(CKK.CKK_XMSSMT, null, null, null, false, "CKK_XMSSMT keys are not part of CNSA 2.0.")]
    [InlineData(CKK.CKK_RSA, null, null, null, false, "CKK_RSA keys are not part of CNSA 2.0.")]
    [InlineData(CKK.CKK_EC, 32, null, null, false, "CKK_EC keys are not part of CNSA 2.0.")]
    [InlineData(CKK.CKK_SLH_DSA, null, null, null, false, "CKK_SLH_DSA keys are not part of CNSA 2.0.")]
    [InlineData(CKK.CKK_SHA256_HMAC, 32, null, null, false, "CKK_SHA256_HMAC keys are not part of CNSA 2.0.")]
    [InlineData(CKK.CKK_DES3, 24, null, null, false, "CKK_DES3 keys are not part of CNSA 2.0.")]
    [InlineData(null, 32, null, null, false, "The token did not report the key's type, so CNSA 2.0 compliance can't be verified.")]
    public void Cnsa20_KeyStrength(CKK? type, int? len, ulong? set, ulong? levels, bool allowed, string? reason)
    {
        PolicyDecision d = Strength(type, len, set, levels);
        Assert.Equal(allowed, d.IsAllowed);
        if (reason is not null)
            Assert.Equal(reason, d.Reason);
    }

    [Theory]
    [InlineData(KeyStrengthSource.Template)]
    [InlineData(KeyStrengthSource.CreatedKey)]
    [InlineData(KeyStrengthSource.ExistingKey)]
    public void Cnsa20_KeyStrength_DoesNotDependOnTheSource(KeyStrengthSource source)
    {
        Assert.True(Policy.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, source) { ValueLengthBytes = 32 }).IsAllowed);
        Assert.False(Policy.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, source) { ValueLengthBytes = 16 }).IsAllowed);
    }

    [Fact]
    public void Cnsa20_RefusesNonSensitiveTemplates_AndKeyExport()
    {
        using var notSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        Assert.False(Policy.Evaluate(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [notSensitive])).IsAllowed);
        foreach (KeyMaterialExportKind kind in Enum.GetValues<KeyMaterialExportKind>())
        {
            PolicyDecision d = Policy.Evaluate(new KeyMaterialExportRequest(kind));
            Assert.False(d.IsAllowed);
            Assert.Contains("CNSA 2.0", d.Reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ToBuilder_OfCnsa20_StillInspects()
    {
        ComposedCryptoPolicy derived = CryptoPolicy.Cnsa20.ToBuilder("MyCnsa").Build();
        Assert.True(derived.InspectsKeys);
        Assert.False(derived.AllowsOverride);
        Assert.Equal(
            "CNSA 2.0 requires AES-256; this is AES-128.",
            derived.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.Template) { ValueLengthBytes = 16 }).Reason);
    }

    [Theory]
    [InlineData("Cnsa20")]
    [InlineData(" cnsa20 ")]
    public void Cnsa20_IsAReservedName(string name)
    {
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder(name));
        Assert.Throws<ArgumentException>(() => CryptoPolicy.Recommended.ToBuilder(name));
    }

    [Fact]
    public void Baseline_SaysTheNsaSourcesAreUnverified()
        => Assert.Contains("pending verification against the NSA documents", Cnsa20Definition.Baseline, StringComparison.Ordinal);

    [Fact]
    public void GeneratedDoc_StatesTheKeyStrengthRule_AndTheKnownLimits()
    {
        string page = PolicyCatalogueMarkdown.Render(Policy.Catalogue, "Cnsa20");
        Assert.Contains("not a certification", page, StringComparison.Ordinal);
        Assert.Contains(Cnsa20Definition.Baseline, page, StringComparison.Ordinal);
        Assert.Contains("| Key strength |", page, StringComparison.Ordinal);
        foreach (string fragment in new[] { "AES-256", "256 bits", "ML-KEM-1024", "ML-DSA-87", "HSS", "XMSS" })
            Assert.Contains(fragment, Policy.Catalogue.KeyStrength.Rationale, StringComparison.Ordinal);
        Assert.Contains("C_SetOperationState", page, StringComparison.Ordinal);
        Assert.Contains("TLS", page, StringComparison.Ordinal);
        Assert.DoesNotContain("NIST-approved security functions", page, StringComparison.Ordinal);
        Assert.DoesNotContain("The size and curve of keys already on the token are not inspected", page, StringComparison.Ordinal);
    }
}
