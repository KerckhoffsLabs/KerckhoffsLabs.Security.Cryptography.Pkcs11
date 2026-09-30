using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009, KLPKCS11010 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class SecureOnlyPolicyTests
{
    private static readonly SecureOnlyPolicy Policy = CryptoPolicy.SecureOnly;

    private static bool Allowed(PolicyRequest r) => Policy.Evaluate(r).IsAllowed;

    private static bool Allowed(CKM mech, CryptoOperation op)
        => Allowed(new MechanismUseRequest(new Mechanism(mech), op));

    private static bool Allowed(Mechanism mech, CryptoOperation op)
        => Allowed(new MechanismUseRequest(mech, op));

    private static string? Reason(PolicyRequest r) => Policy.Evaluate(r).Reason;

    private static string? Reason(CKM mech, CryptoOperation op)
        => Reason(new MechanismUseRequest(new Mechanism(mech), op));

    private static string? Reason(Mechanism mech, CryptoOperation op)
        => Reason(new MechanismUseRequest(mech, op));

    [Fact]
    public void Identity()
    {
        Assert.Equal("SecureOnly", Policy.Name);
        Assert.True(Policy.AllowsOverride);
        Assert.Same(CryptoPolicy.SecureOnly, Policy);
    }

    // === Deny by default ===================================================

    [Fact]
    public void EveryMechanismNotOnTheAllowList_IsDeniedForEveryOperation()
    {
        var allowed = Policy.Catalogue.AllowedMechanisms;
        foreach (CKM mech in Enum.GetValues<CKM>().Where(m => !allowed.ContainsKey(m)))
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
                Assert.False(Allowed(mech, op), $"{mech} was allowed for {op}");
    }

    [Theory]
    [InlineData(0x8000_0001UL)]
    [InlineData(0x8000_1234UL)]
    [InlineData(0xFFFF_FFF0UL)]
    public void VendorMechanism_IsDeniedForEveryOperation(ulong vendor)
    {
        foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
            Assert.False(Allowed(new Mechanism((CKM)vendor), op), $"0x{vendor:X} was allowed for {op}");
    }

    [Fact]
    public void EveryAllowedEntry_IsAllowedExactlyForItsListedOperations()
    {
        foreach ((CKM mech, MechanismRule rule) in Policy.Catalogue.AllowedMechanisms)
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
            {
                bool listed = rule.Operations.Contains(op) || rule.LegacyOperations.Contains(op);
                PolicyDecision d = Policy.Evaluate(new MechanismUseRequest(ValidMechanismFor(mech), op));
                Assert.True(listed == d.IsAllowed, $"{mech} / {op}: listed={listed}, verdict={d.IsAllowed} ({d.Reason})");
            }
    }

    // A parameter-checked entry needs valid parameters for its "listed" operations to pass.
    internal static Mechanism ValidMechanismFor(CKM mech) => mech switch
    {
        CKM.CKM_RSA_PKCS_OAEP => new Mechanism(mech, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)),
        CKM.CKM_RSA_PKCS_PSS => new Mechanism(mech, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32)),
        CKM.CKM_HASH_ML_DSA or CKM.CKM_HASH_SLH_DSA => new Mechanism(mech, new CkmHashPqcSignParams(CKM.CKM_SHA256)),
        CKM.CKM_PKCS5_PBKD2 => new Mechanism(mech, new CkmPkcs5Pbkd2Params([1], 1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, [1])),
        CKM.CKM_SP800_108_COUNTER_KDF => new Mechanism(mech, CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC).IterationCounter().Build()),
        CKM.CKM_SP800_108_FEEDBACK_KDF => new Mechanism(mech, CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC).IterationCounter().Build()),
        CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF => new Mechanism(mech, CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC).IterationCounter().Build()),
        CKM.CKM_HKDF_DERIVE =>
            new Mechanism(mech, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC)),
        CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE =>
            new Mechanism(mech, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, [0x04, 0x01, 0x04])),
        _ => new Mechanism(mech),
    };

    // Golden list: SecureOnly's allowed mechanisms and their exact operations. Adding, removing or
    // widening an entry must be a deliberate edit here. OAEP and ECDH also carry Encapsulate /
    // Decapsulate (their PKCS#11 v3.2 KEM use).
    private static readonly Dictionary<CKM, CryptoOperations> ExpectedAllowList = BuildExpectedAllowList();

    private static Dictionary<CKM, CryptoOperations> BuildExpectedAllowList()
    {
        const CryptoOperations cipher = CryptoOperations.Encrypt | CryptoOperations.Decrypt | CryptoOperations.Wrap | CryptoOperations.Unwrap;
        const CryptoOperations signature = CryptoOperations.Sign | CryptoOperations.Verify;
        const CryptoOperations kem = CryptoOperations.Encapsulate | CryptoOperations.Decapsulate;
        var expected = new Dictionary<CKM, CryptoOperations>();
        void Add(CryptoOperations ops, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) expected.Add(m, ops);
        }

        Add(cipher, CKM.CKM_AES_GCM, CKM.CKM_AES_CCM, CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP, CKM.CKM_AES_KEY_WRAP_PAD,
            CKM.CKM_CHACHA20_POLY1305);
        Add(signature, CKM.CKM_AES_CMAC, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_AES_GMAC);
        Add(CryptoOperations.GenerateKey, CKM.CKM_AES_KEY_GEN, CKM.CKM_CHACHA20_KEY_GEN);
        Add(CryptoOperations.Digest, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512);
        Add(signature, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA256_HMAC_GENERAL, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL,
            CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_256_HMAC_GENERAL,
            CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_384_HMAC_GENERAL, CKM.CKM_SHA3_512_HMAC, CKM.CKM_SHA3_512_HMAC_GENERAL);
        Add(CryptoOperations.GenerateKey, CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA256_KEY_GEN, CKM.CKM_SHA384_KEY_GEN,
            CKM.CKM_SHA512_KEY_GEN, CKM.CKM_SHA3_256_KEY_GEN, CKM.CKM_SHA3_384_KEY_GEN, CKM.CKM_SHA3_512_KEY_GEN);
        Add(signature, CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_SHA3_256_RSA_PKCS_PSS, CKM.CKM_SHA3_384_RSA_PKCS_PSS, CKM.CKM_SHA3_512_RSA_PKCS_PSS, CKM.CKM_RSA_PKCS_PSS,
            CKM.CKM_SHA256_RSA_PKCS, CKM.CKM_SHA384_RSA_PKCS, CKM.CKM_SHA512_RSA_PKCS,
            CKM.CKM_SHA3_256_RSA_PKCS, CKM.CKM_SHA3_384_RSA_PKCS, CKM.CKM_SHA3_512_RSA_PKCS);
        Add(cipher | kem, CKM.CKM_RSA_PKCS_OAEP);
        Add(CryptoOperations.GenerateKeyPair, CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        Add(signature, CKM.CKM_ECDSA, CKM.CKM_ECDSA_SHA256, CKM.CKM_ECDSA_SHA384, CKM.CKM_ECDSA_SHA512,
            CKM.CKM_ECDSA_SHA3_256, CKM.CKM_ECDSA_SHA3_384, CKM.CKM_ECDSA_SHA3_512, CKM.CKM_EDDSA);
        Add(CryptoOperations.GenerateKeyPair, CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        Add(CryptoOperations.Derive | kem, CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE);
        Add(kem, CKM.CKM_ML_KEM);
        Add(signature, CKM.CKM_ML_DSA, CKM.CKM_SLH_DSA, CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_SLH_DSA,
            CKM.CKM_HASH_ML_DSA_SHA256, CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_HASH_ML_DSA_SHA512,
            CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_HASH_ML_DSA_SHA3_512,
            CKM.CKM_HASH_ML_DSA_SHAKE128, CKM.CKM_HASH_ML_DSA_SHAKE256,
            CKM.CKM_HASH_SLH_DSA_SHA256, CKM.CKM_HASH_SLH_DSA_SHA384, CKM.CKM_HASH_SLH_DSA_SHA512,
            CKM.CKM_HASH_SLH_DSA_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_384, CKM.CKM_HASH_SLH_DSA_SHA3_512,
            CKM.CKM_HASH_SLH_DSA_SHAKE128, CKM.CKM_HASH_SLH_DSA_SHAKE256);
        Add(CryptoOperations.GenerateKeyPair, CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA_KEY_PAIR_GEN);
        Add(CryptoOperations.Derive, CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF,
            CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF, CKM.CKM_HKDF_DERIVE);
        Add(CryptoOperations.GenerateKey, CKM.CKM_HKDF_KEY_GEN);
        Add(CryptoOperations.GenerateKey | CryptoOperations.Derive, CKM.CKM_PKCS5_PBKD2);
        return expected;
    }

    [Fact]
    public void AllowList_MatchesTheGoldenList()
    {
        var actual = Policy.Catalogue.AllowedMechanisms;
        Assert.Equal(
            ExpectedAllowList.Keys.Select(MechanismNames.Of).Order(StringComparer.Ordinal),
            actual.Keys.Select(MechanismNames.Of).Order(StringComparer.Ordinal));
        foreach ((CKM mech, CryptoOperations ops) in ExpectedAllowList)
        {
            Assert.True(ops == actual[mech].Operations, $"{MechanismNames.Of(mech)}: expected {ops}, got {actual[mech].Operations}");
            Assert.Equal(CryptoOperations.None, actual[mech].LegacyOperations);
        }
        Assert.Empty(Policy.Catalogue.AllowedVendorMechanisms);
    }

    [Theory]
    [InlineData(CKM.CKM_AES_GCM, CryptoOperation.Encrypt)]
    [InlineData(CKM.CKM_AES_CCM, CryptoOperation.Unwrap)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP, CryptoOperation.Wrap)]
    [InlineData(CKM.CKM_AES_CMAC, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_AES_KEY_GEN, CryptoOperation.GenerateKey)]
    [InlineData(CKM.CKM_CHACHA20_POLY1305, CryptoOperation.Decrypt)]
    [InlineData(CKM.CKM_SHA256, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA512_256, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA3_512_HMAC_GENERAL, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_GENERIC_SECRET_KEY_GEN, CryptoOperation.GenerateKey)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_ECDSA_SHA384, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_EDDSA, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_ECDH1_DERIVE, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    [InlineData(CKM.CKM_ML_KEM, CryptoOperation.Decapsulate)]
    [InlineData(CKM.CKM_HASH_ML_DSA_SHAKE256, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    public void Allowed_ForItsOperation(CKM mech, CryptoOperation op) => Assert.True(Allowed(ValidMechanismFor(mech), op));

    [Theory]
    [InlineData(CKM.CKM_AES_GCM, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SHA256, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_SHA256_HMAC, CryptoOperation.Encrypt)]
    [InlineData(CKM.CKM_AES_KEY_GEN, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_ECDSA_SHA256, CryptoOperation.Decrypt)]
    [InlineData(CKM.CKM_ML_KEM, CryptoOperation.Sign)]
    public void Denied_OutsideItsOperations_WithTheOperationRestrictedWording(CKM mech, CryptoOperation op)
    {
        string? reason = Reason(mech, op);
        Assert.StartsWith($"{mech} is allowed under SecureOnly only for ", reason, StringComparison.Ordinal);
        Assert.Contains($"; {op} is not.", reason, StringComparison.Ordinal);
        Assert.DoesNotContain("WithAllowedMechanism", reason, StringComparison.Ordinal);
    }

    // PKCS#11 v3.2 KEM use of the classical key-transport / key-agreement mechanisms: allowed under
    // SecureOnly (the OAEP parameter check still applies), not under FipsOnly.
    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS_OAEP)]
    [InlineData(CKM.CKM_ECDH1_DERIVE)]
    [InlineData(CKM.CKM_ECDH1_COFACTOR_DERIVE)]
    public void ClassicalKem_IsAllowedForEncapsulation_UnderSecureOnlyOnly(CKM mech)
    {
        Mechanism m = ValidMechanismFor(mech);
        foreach (CryptoOperation op in (CryptoOperation[])[CryptoOperation.Encapsulate, CryptoOperation.Decapsulate])
        {
            Assert.True(Allowed(m, op), $"SecureOnly {mech} {op}");
            Assert.False(CryptoPolicy.FipsOnly.Evaluate(new MechanismUseRequest(m, op)).IsAllowed, $"FipsOnly {mech} {op}");
        }
        if (mech == CKM.CKM_RSA_PKCS_OAEP)
            Assert.False(Allowed(new Mechanism(mech), CryptoOperation.Encapsulate));
    }

    // === Newly documented refusals =========================================

    [Theory]
    [InlineData(CKM.CKM_AES_MAC, CryptoOperation.Sign)]
    [InlineData(CKM.CKM_DES3_CMAC, CryptoOperation.Verify)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7, CryptoOperation.Wrap)]
    [InlineData(CKM.CKM_SHA224, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_SHA512_T, CryptoOperation.Digest)]
    [InlineData(CKM.CKM_DSA_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    [InlineData(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, CryptoOperation.GenerateKeyPair)]
    [InlineData(CKM.CKM_SHA256_KEY_DERIVATION, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_SHAKE_128_KEY_DERIVE, CryptoOperation.Derive)]
    [InlineData(CKM.CKM_IKE2_PRF_PLUS_DERIVE, CryptoOperation.Derive)]
    public void NewlyDocumentedRefusal_IsDeniedWithItsReason(CKM mech, CryptoOperation op)
    {
        Assert.True(Policy.Catalogue.DocumentedRefusedMechanisms.ContainsKey(mech));
        Assert.StartsWith($"{MechanismNames.Of(mech)} is not allowed: ", Reason(mech, op), StringComparison.Ordinal);
    }

    // === Wording ===========================================================

    [Fact]
    public void DocumentedRefusal_QuotesReasonAndAlternative()
    {
        DocumentedRefusal refusal = Policy.Catalogue.DocumentedRefusedMechanisms[CKM.CKM_DES_CBC];
        Assert.NotNull(refusal.Alternative);
        Assert.Equal(
            $"CKM_DES_CBC is not allowed: {refusal.Reason} Use {refusal.Alternative}.",
            Reason(CKM.CKM_DES_CBC, CryptoOperation.Encrypt));
    }

    [Fact]
    public void DocumentedRefusal_WithoutAlternative_OmitsTheUseSentence()
    {
        DocumentedRefusal refusal = Policy.Catalogue.DocumentedRefusedMechanisms[CKM.CKM_EXTRACT_KEY_FROM_KEY];
        Assert.Null(refusal.Alternative);
        Assert.Equal($"CKM_EXTRACT_KEY_FROM_KEY is not allowed: {refusal.Reason}", Reason(CKM.CKM_EXTRACT_KEY_FROM_KEY, CryptoOperation.Derive));
    }

    [Fact]
    public void UnlistedMechanism_SaysNotReviewed_AndNamesTheExtensionPoint()
    {
        Assert.False(Policy.Catalogue.DocumentedRefusedMechanisms.ContainsKey(CKM.CKM_CAMELLIA_CBC));
        Assert.Equal(
            "CKM_CAMELLIA_CBC is not on the SecureOnly allow-list (not reviewed). " +
            "If you have reviewed it, add it with CryptoPolicy.SecureOnly.WithAllowedMechanism(...).",
            Reason(CKM.CKM_CAMELLIA_CBC, CryptoOperation.Encrypt));
    }

    [Fact]
    public void VendorMechanism_SaysNotReviewed_AndNamesTheExtensionPoint()
    {
        string? reason = Reason(new MechanismUseRequest(new Mechanism((CKM)0x8000_1234UL), CryptoOperation.Sign));
        Assert.StartsWith("vendor mechanism 0x80001234 is not on the SecureOnly allow-list (not reviewed).", reason, StringComparison.Ordinal);
        Assert.Contains("WithAllowedMechanism", reason, StringComparison.Ordinal);
    }

    // WithAllowedMechanism adds mechanisms only, so unlisted hashes, curves and KDFs must not point at it.
    [Fact]
    public void UnlistedHashCurveAndKdf_DoNotNameTheExtensionPoint()
    {
        string?[] reasons =
        [
            Reason(new HashUseRequest(new HashAlgorithmName("RIPEMD160"), CryptoOperation.Sign)),
            Reason(new EcKeyGenerationRequest(Pkcs11ECCurve.CreateFromValue("1.3.6.1.4.1.99999.1"))),
            Reason(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, (CKD)0x7777)),
        ];
        Assert.All(reasons, reason =>
        {
            Assert.EndsWith("is not on the SecureOnly allow-list (not reviewed).", reason, StringComparison.Ordinal);
            Assert.DoesNotContain("WithAllowedMechanism", reason, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Denials_DoNotMentionTheRemovedOptIn()
    {
        IEnumerable<PolicyDecision> denials = Enum.GetValues<CKM>()
            .Select(mech => Policy.Evaluate(new MechanismUseRequest(new Mechanism(mech), CryptoOperation.Encrypt)))
            .Where(d => !d.IsAllowed);

        foreach (PolicyDecision d in denials)
            Assert.DoesNotContain("AllowInsecure", d.Reason, StringComparison.Ordinal);
    }

    // === Parameter checks ==================================================

    [Fact]
    public void Oaep_RequiresParametersWithAnAllowedHash()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP), CryptoOperation.Encrypt));
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)), CryptoOperation.Encrypt));
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224)), CryptoOperation.Decrypt));
        Assert.True(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.Encrypt));
        Assert.True(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA3_512, CKG.CKG_MGF1_SHA3_512)), CryptoOperation.Unwrap));
    }

    [Fact]
    public void RawPss_RequiresParametersWithAnAllowedHashAndBoundedSalt()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_PSS), CryptoOperation.Sign));
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1, 20)), CryptoOperation.Verify));
        Assert.False(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 33)), CryptoOperation.Sign));
        Assert.True(Allowed(new Mechanism(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32)), CryptoOperation.Sign));
    }

    [Fact]
    public void HashBoundPss_ChecksParametersOnlyWhenGiven()
    {
        Assert.True(Allowed(new Mechanism(CKM.CKM_SHA384_RSA_PKCS_PSS), CryptoOperation.Sign));
        Assert.True(Allowed(new Mechanism(CKM.CKM_SHA384_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, 48)), CryptoOperation.Sign));
        Assert.False(Allowed(new Mechanism(CKM.CKM_SHA384_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224, 28)), CryptoOperation.Sign));
    }

    [Theory]
    [InlineData(CKM.CKM_SHA256, true)]
    [InlineData(CKM.CKM_SHA3_384, true)]
    [InlineData(CKM.CKM_SHA224, false)]
    [InlineData(CKM.CKM_SHA_1, false)]
    public void GenericPqcPreHash_RequiresAtLeast256Bits(CKM hash, bool allowed)
    {
        var mech = new Mechanism(CKM.CKM_HASH_ML_DSA, new CkmHashPqcSignParams(hash));
        Assert.Equal(allowed, Allowed(mech, CryptoOperation.Sign));
        Assert.False(Allowed(new Mechanism(CKM.CKM_HASH_SLH_DSA), CryptoOperation.Sign));
    }

    // === KDF PRF checks =====================================================

    [Theory]
    [InlineData(CKP.CKP_PKCS5_PBKD2_HMAC_SHA256)]
    [InlineData(CKP.CKP_PKCS5_PBKD2_HMAC_SHA384)]
    [InlineData(CKP.CKP_PKCS5_PBKD2_HMAC_SHA512)]
    [InlineData(CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256)]
    public void Pbkdf2_AllowedPrf_IsAllowed(CKP prf)
    {
        var mech = new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params([1], 1, prf, [1]));
        Assert.True(Allowed(mech, CryptoOperation.GenerateKey));
    }

    [Fact]
    public void Pbkdf2_HmacSha1_IsDenied()
    {
        var mech = new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params([1], 1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, [1]));
        Assert.False(Allowed(mech, CryptoOperation.GenerateKey));
        Assert.Contains("CKP_PKCS5_PBKD2_HMAC_SHA1 is not allowed as a PBKDF2 PRF: ", Reason(mech, CryptoOperation.GenerateKey), StringComparison.Ordinal);
    }

    [Fact]
    public void Pbkdf2_WithoutOrWithWrongParameters_IsDenied()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_PKCS5_PBKD2), CryptoOperation.GenerateKey));
        Assert.False(Allowed(new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.GenerateKey));
    }

    [Theory]
    [InlineData(CKM.CKM_SHA256_HMAC)]
    [InlineData(CKM.CKM_SHA384_HMAC)]
    [InlineData(CKM.CKM_SHA512_HMAC)]
    [InlineData(CKM.CKM_SHA3_256_HMAC)]
    [InlineData(CKM.CKM_SHA3_384_HMAC)]
    [InlineData(CKM.CKM_SHA3_512_HMAC)]
    [InlineData(CKM.CKM_AES_CMAC)]
    public void Sp800108_AllowedPrf_IsAllowed(CKM prf)
    {
        var mech = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.Counter(prf).IterationCounter().Build());
        Assert.True(Allowed(mech, CryptoOperation.Derive));
    }

    [Fact]
    public void Sp800108_HmacSha1_IsDenied()
    {
        var mech = new Mechanism(CKM.CKM_SP800_108_FEEDBACK_KDF, CkmSp800108KdfParams.Feedback(CKM.CKM_SHA_1_HMAC).IterationCounter().Build());
        Assert.False(Allowed(mech, CryptoOperation.Derive));
        Assert.Contains("CKM_SHA_1_HMAC is not allowed as a SP 800-108 PRF: ", Reason(mech, CryptoOperation.Derive), StringComparison.Ordinal);
    }

    [Fact]
    public void Sp800108_WithoutOrWithWrongParameters_IsDenied()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF), CryptoOperation.Derive));
        Assert.False(Allowed(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.Derive));
    }

    [Theory]
    [InlineData(CKM.CKM_SHA256)]
    [InlineData(CKM.CKM_SHA384)]
    [InlineData(CKM.CKM_SHA512)]
    [InlineData(CKM.CKM_SHA3_256)]
    [InlineData(CKM.CKM_SHA3_384)]
    [InlineData(CKM.CKM_SHA3_512)]
    [InlineData(CKM.CKM_SHA256_HMAC)]
    [InlineData(CKM.CKM_SHA384_HMAC)]
    [InlineData(CKM.CKM_SHA512_HMAC)]
    [InlineData(CKM.CKM_SHA3_256_HMAC)]
    [InlineData(CKM.CKM_SHA3_384_HMAC)]
    [InlineData(CKM.CKM_SHA3_512_HMAC)]
    public void Hkdf_AllowedPrf_IsAllowed(CKM prf)
    {
        var mech = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, prf));
        Assert.True(Allowed(mech, CryptoOperation.Derive));
    }

    [Fact]
    public void Hkdf_Sha1_IsDenied()
    {
        var mech = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA_1));
        Assert.False(Allowed(mech, CryptoOperation.Derive));
        Assert.Contains("CKM_SHA_1 is not an allowed HKDF PRF; use ", Reason(mech, CryptoOperation.Derive), StringComparison.Ordinal);
    }

    [Fact]
    public void Hkdf_WithoutOrWithWrongParameters_IsDenied()
    {
        Assert.False(Allowed(new Mechanism(CKM.CKM_HKDF_DERIVE), CryptoOperation.Derive));
        Assert.False(Allowed(new Mechanism(CKM.CKM_HKDF_DERIVE, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), CryptoOperation.Derive));
    }

    [Fact]
    public void DocumentedRefusedPrf_QuotesReasonAndAlternative()
    {
        DocumentedRefusal refusal = Policy.Catalogue.DocumentedRefusedPrfs[nameof(CKP.CKP_PKCS5_PBKD2_HMAC_SHA1)];
        Assert.NotNull(refusal.Alternative);
        var mech = new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params([1], 1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, [1]));
        Assert.Equal(
            $"CKP_PKCS5_PBKD2_HMAC_SHA1 is not allowed as a PBKDF2 PRF: {refusal.Reason} Use {refusal.Alternative}.",
            Reason(mech, CryptoOperation.GenerateKey));
    }

    // === Rules, hashes, curves, KDFs =======================================

    [Theory]
    [InlineData(1024, false)]
    [InlineData(2047, false)]
    [InlineData(2048, true)]
    [InlineData(4096, true)]
    public void RsaKeyGeneration_Floor(int bits, bool allowed)
        => Assert.Equal(allowed, Allowed(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, bits)));

    [Fact]
    public void RsaKeyGeneration_X931_IsDocumentedRefused()
        => Assert.StartsWith("CKM_RSA_X9_31_KEY_PAIR_GEN is not allowed: ",
            Reason(new RsaKeyGenerationRequest(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, 4096)), StringComparison.Ordinal);

    [Fact]
    public void RsaKeyGeneration_ForANonRsaMechanism_IsDenied()
        => Assert.False(Allowed(new RsaKeyGenerationRequest(CKM.CKM_EC_KEY_PAIR_GEN, 4096)));

    [Fact]
    public void EcKeyGeneration_CurveAllowList()
    {
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP521)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.Secp256k1)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.BrainpoolP256r1)));
        Assert.True(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.BrainpoolP512t1)));
        Assert.False(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP224)));
        Assert.False(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.BrainpoolP224r1)));
        Assert.False(Allowed(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.Sm2)));
        // An unknown OID is not reviewed, so it is denied.
        Assert.Contains("not on the SecureOnly allow-list",
            Reason(new EcKeyGenerationRequest(Pkcs11ECCurve.CreateFromValue("1.3.6.1.4.1.99999.1"))), StringComparison.Ordinal);
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

    [Theory]
    [InlineData(CKD.CKD_SHA256_KDF, true)]
    [InlineData(CKD.CKD_SHA512_KDF_SP800, true)]
    [InlineData(CKD.CKD_SHA3_256_KDF, true)]
    [InlineData(CKD.CKD_SHA3_384_KDF_SP800, true)]
    [InlineData(CKD.CKD_NULL, false)]
    [InlineData(CKD.CKD_SHA1_KDF, false)]
    [InlineData(CKD.CKD_SHA224_KDF, false)]
    [InlineData(CKD.CKD_SHA3_224_KDF_SP800, false)]
    [InlineData(CKD.CKD_BLAKE2B_256_KDF, false)]
    [InlineData(CKD.CKD_CPDIVERSIFY_KDF, false)]
    public void KeyAgreementKdf_AllowList(CKD kdf, bool allowed)
        => Assert.Equal(allowed, Allowed(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, kdf)));

    [Fact]
    public void KeyAgreementKdf_UnknownValue_IsDenied()
        => Assert.False(Allowed(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, (CKD)0x7777)));

    [Fact]
    public void HashUse_AllowList()
    {
        Assert.True(Allowed(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)));
        Assert.True(Allowed(new HashUseRequest(HashAlgorithmName.SHA3_512, CryptoOperation.Verify)));
        Assert.False(Allowed(new HashUseRequest(HashAlgorithmName.SHA1, CryptoOperation.Sign)));
        Assert.False(Allowed(new HashUseRequest(HashAlgorithmName.SHA1, CryptoOperation.Verify)));
        Assert.False(Allowed(new HashUseRequest(HashAlgorithmName.MD5, CryptoOperation.Verify)));
        Assert.False(Allowed(new HashUseRequest(new HashAlgorithmName("SHA224"), CryptoOperation.Sign)));
        Assert.Contains("not on the SecureOnly allow-list",
            Reason(new HashUseRequest(new HashAlgorithmName("BLAKE2B"), CryptoOperation.Sign)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(KeyMaterialExportKind.EcdhSharedSecret)]
    [InlineData(KeyMaterialExportKind.KemSharedSecret)]
    [InlineData(KeyMaterialExportKind.KdfOutput)]
    [InlineData(KeyMaterialExportKind.PasswordKdfOutput)]
    public void KeyMaterialExport_Refused(KeyMaterialExportKind kind)
        => Assert.False(Allowed(new KeyMaterialExportRequest(kind)));

    [Fact]
    public void UnrecognizedRequestKind_IsDenied()
        => Assert.False(Allowed(new UnrecognizedPolicyRequest()));
}
