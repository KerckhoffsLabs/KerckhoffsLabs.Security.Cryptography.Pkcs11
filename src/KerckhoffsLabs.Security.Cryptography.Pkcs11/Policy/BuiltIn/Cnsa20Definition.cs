using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

/// <summary>
/// The definition of <see cref="CryptoPolicy.Cnsa20"/>: only the NSA CNSA 2.0 algorithms at their CNSA 2.0 sizes
/// (<see cref="Baseline"/>). Anything not on the list, including vendor-defined mechanisms, is refused.
/// </summary>
/// <remarks>
/// <para>
/// CNSA 2.0 names algorithms and sizes, not modes. Where it is silent the policy stays narrow: AES only as GCM
/// (128-bit tag) and KW/KWP, SHA-384/512 only, HMAC and the SP 800-108 / HKDF KDFs only over SHA-384/512 (needed to
/// turn an ML-KEM shared secret into an AES key on the token), and pure ML-DSA only (no HashML-DSA).
/// </para>
/// <para>
/// Key sizes are judged by <see cref="Cnsa20Wording.JudgeKeyStrength"/> through <see cref="KeyStrengthRequest"/>,
/// which the session raises for templates, created keys and every use of an existing key. A key whose size the
/// token does not report is refused.
/// </para>
/// <para>
/// Every mechanism, hash, curve, key-agreement KDF and key-agreement key type that <c>Recommended</c> or
/// <c>NistApproved</c> allows is either allowed here or documented as refused with its CNSA 2.0 alternative.
/// </para>
/// </remarks>
internal static class Cnsa20Definition
{
    /// <summary>The sources this table reflects.</summary>
    internal const string Baseline =
        "NSA CNSA 2.0 (CSA Sept 2022; FAQ v2.2) — cited from secondary sources pending verification against the NSA documents; " +
        "FIPS 197, FIPS 180-4, FIPS 203, FIPS 204, SP 800-208, SP 800-38D, SP 800-38F, SP 800-108r1, SP 800-56C Rev.2";

    private const S Cipher = S.Encrypt | S.Decrypt | S.Wrap | S.Unwrap;
    private const S Signature = S.Sign | S.Verify;

    private const S AnyOperation =
        S.Encrypt | S.Decrypt | S.Sign | S.Verify | S.Wrap | S.Unwrap | S.Derive | S.Digest |
        S.GenerateKey | S.GenerateKeyPair | S.Encapsulate | S.Decapsulate;

    /// <summary>Builds the Cnsa20 policy.</summary>
    internal static ComposedCryptoPolicy Create()
    {
        // RsaKeyGenerationRule keeps the builder default: RSA key generation is unreachable, its mechanism is refused.
        CryptoPolicyBuilder b = CryptoPolicyBuilder.ForBuiltIn("Cnsa20")
            .WithBuiltInReference("CryptoPolicy.Cnsa20")
            .WithDocumentation(PolicyDocumentation.Cnsa20)
            .AllowsOverride(false)
            .WithKeyTemplateRule(KeyTemplateRule.RequireSensitive(
                "Keys stay on the token: a key template with CKA_SENSITIVE=false is refused (CNSA 2.0 policy).",
                "CNSA 2.0 (this policy): keys stay on the token; CKA_SENSITIVE=false is refused."))
            .WithKeyMaterialExportRule(KeyMaterialExportRule.Refuse(
                "Reading key material off the token in plaintext is refused (CNSA 2.0 policy); wrap it with AES-256 KW/KWP or GCM instead.",
                kind => $"CNSA 2.0 (this policy): reading the {kind} off the token in plaintext is refused; wrap it with AES-256 KW/KWP or GCM instead."))
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(Cnsa20Wording.JudgeKeyStrength, Cnsa20Wording.KeyStrengthRationale));
        foreach ((CKM mechanism, MechanismRule rule) in BuildAllowedMechanisms()) b.AllowRule(mechanism, rule);
        foreach ((string name, AllowedHash hash) in BuildAllowedHashes()) b.AllowHash(name, hash.Operations, hash.Rationale);
        foreach ((CKM mechanism, DocumentedRefusal refusal) in BuildDocumentedRefusedMechanisms()) b.DocumentRefusedMechanism(mechanism, refusal);
        foreach ((string hash, DocumentedRefusal refusal) in BuildDocumentedRefusedHashes()) b.DocumentRefusedHash(hash, refusal);
        foreach ((string oid, DocumentedRefusal refusal) in BuildDocumentedRefusedCurves()) b.DocumentRefusedCurve(oid, refusal);
        foreach ((CKD kdf, DocumentedRefusal refusal) in BuildDocumentedRefusedKdfs()) b.DocumentRefusedKdf(kdf, refusal);
        foreach ((string prf, DocumentedRefusal refusal) in BuildDocumentedRefusedPrfs()) b.DocumentRefusedPrf(prf, refusal);
        var keyAgreement = new DocumentedRefusal(
            "CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM replaces ECDH.",
            "CKM_ML_KEM with an ML-KEM-1024 key");
        b.DocumentRefusedKeyAgreementKeyType(CKK.CKK_EC, keyAgreement);
        b.DocumentRefusedKeyAgreementKeyType(CKK.CKK_EC_MONTGOMERY, keyAgreement);
        return b.Build();
    }

    // --- Mechanisms ---

    private static FrozenDictionary<CKM, MechanismRule> BuildAllowedMechanisms()
    {
        var rules = new Dictionary<CKM, MechanismRule>();

        void Allow(S ops, string citation, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new MechanismRule(ops, S.None, null, citation);
        }
        void AllowChecked(S ops, string citation, MechanismCheck check, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new MechanismRule(ops, S.None, check, citation);
        }

        // --- AES-256 (FIPS 197): GCM and KW/KWP only; the key length is the key-strength rule's ---
        AllowChecked(Cipher, "CNSA 2.0 AES-256 (FIPS 197) in GCM (SP 800-38D), 128-bit tag", Cnsa20Wording.GcmTag, CKM.CKM_AES_GCM);
        Allow(Cipher, "CNSA 2.0 AES-256 (FIPS 197) key wrap (SP 800-38F)", CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP);
        Allow(S.GenerateKey, "CNSA 2.0 AES-256 (FIPS 197); CKA_VALUE_LEN must be 32", CKM.CKM_AES_KEY_GEN);

        // --- SHA-384 / SHA-512 (FIPS 180-4) and HMAC over them ---
        Allow(S.Digest, "CNSA 2.0 SHA-384 / SHA-512 (FIPS 180-4)", CKM.CKM_SHA384, CKM.CKM_SHA512);
        Allow(Signature, "HMAC over CNSA 2.0 SHA-384 / SHA-512 (FIPS 198-1), key of at least 256 bits",
            CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL);
        Allow(S.GenerateKey, "Secret / HMAC key generation, at least 256 bits",
            CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA384_KEY_GEN, CKM.CKM_SHA512_KEY_GEN, CKM.CKM_HKDF_KEY_GEN);

        // --- KDFs over SHA-384 / SHA-512 ---
        AllowChecked(S.Derive, "SP 800-108r1 over HMAC-SHA-384 / HMAC-SHA-512", Cnsa20Wording.Sp800108Prf,
            CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF);
        AllowChecked(S.Derive, "SP 800-56C Rev.2 HKDF over SHA-384 / SHA-512", Cnsa20Wording.HkdfPrf,
            CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA);

        // --- Post-quantum: ML-KEM-1024, ML-DSA-87, LMS / XMSS; sizes are the key-strength rule's ---
        Allow(S.Encapsulate | S.Decapsulate, "CNSA 2.0 ML-KEM-1024 (FIPS 203)", CKM.CKM_ML_KEM);
        Allow(Signature, "CNSA 2.0 ML-DSA-87 (FIPS 204)", CKM.CKM_ML_DSA);
        Allow(Signature, "CNSA 2.0 LMS (single-level HSS) / XMSS (SP 800-208)", CKM.CKM_HSS, CKM.CKM_XMSS);
        Allow(S.GenerateKeyPair, "CNSA 2.0 ML-KEM-1024 / ML-DSA-87 (FIPS 203 / 204), LMS / XMSS (SP 800-208)",
            CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_HSS_KEY_PAIR_GEN, CKM.CKM_XMSS_KEY_PAIR_GEN);

        return rules.ToFrozenDictionary();
    }

    /// <summary>
    /// The mechanisms that <c>Recommended</c> or <c>NistApproved</c> allow (and a few close relatives) but CNSA 2.0
    /// excludes, each with its CNSA 2.0 alternative.
    /// </summary>
    private static FrozenDictionary<CKM, DocumentedRefusal> BuildDocumentedRefusedMechanisms()
    {
        var refused = new Dictionary<CKM, DocumentedRefusal>();

        void Refuse(string reason, string? alternative, params CKM[] mechanisms)
        {
            var refusal = new DocumentedRefusal(reason, alternative);
            foreach (CKM m in mechanisms) refused[m] = refusal;
        }

        const string MlDsa = "CKM_ML_DSA with an ML-DSA-87 key";
        const string MlKem = "CKM_ML_KEM with an ML-KEM-1024 key";
        const string AesGcmOrKw = "CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys";
        const string Sha384Or512 = "CKM_SHA384 or CKM_SHA512";
        const string HmacSha384Or512 = "CKM_SHA384_HMAC or CKM_SHA512_HMAC";

        // --- RSA (all) ---
        Refuse("CNSA 2.0 replaces RSA signatures with ML-DSA-87.", MlDsa,
            CKM.CKM_RSA_PKCS_PSS, CKM.CKM_SHA1_RSA_PKCS, CKM.CKM_SHA1_RSA_PKCS_PSS,
            CKM.CKM_SHA224_RSA_PKCS, CKM.CKM_SHA256_RSA_PKCS, CKM.CKM_SHA384_RSA_PKCS, CKM.CKM_SHA512_RSA_PKCS,
            CKM.CKM_SHA3_224_RSA_PKCS, CKM.CKM_SHA3_256_RSA_PKCS, CKM.CKM_SHA3_384_RSA_PKCS, CKM.CKM_SHA3_512_RSA_PKCS,
            CKM.CKM_SHA224_RSA_PKCS_PSS, CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_SHA3_224_RSA_PKCS_PSS, CKM.CKM_SHA3_256_RSA_PKCS_PSS, CKM.CKM_SHA3_384_RSA_PKCS_PSS, CKM.CKM_SHA3_512_RSA_PKCS_PSS);
        Refuse("CNSA 2.0 replaces RSA key establishment with ML-KEM-1024.", MlKem, CKM.CKM_RSA_PKCS_OAEP);
        Refuse("CNSA 2.0 replaces RSA signatures with ML-DSA-87 and RSA key establishment with ML-KEM-1024.",
            "CKM_ML_DSA (ML-DSA-87) to sign, CKM_ML_KEM (ML-KEM-1024) to establish keys",
            CKM.CKM_RSA_PKCS, CKM.CKM_RSA_X_509);
        Refuse("CNSA 2.0 has no RSA; generate ML-DSA-87 or ML-KEM-1024 key pairs instead.",
            "CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN",
            CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_X9_31_KEY_PAIR_GEN);

        // --- DSA, ECDSA, EdDSA ---
        Refuse("CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them.", MlDsa,
            CKM.CKM_DSA, CKM.CKM_DSA_SHA1, CKM.CKM_DSA_SHA224, CKM.CKM_DSA_SHA256, CKM.CKM_DSA_SHA384, CKM.CKM_DSA_SHA512,
            CKM.CKM_DSA_SHA3_224, CKM.CKM_DSA_SHA3_256, CKM.CKM_DSA_SHA3_384, CKM.CKM_DSA_SHA3_512,
            CKM.CKM_ECDSA, CKM.CKM_ECDSA_SHA1, CKM.CKM_ECDSA_SHA224, CKM.CKM_ECDSA_SHA256, CKM.CKM_ECDSA_SHA384, CKM.CKM_ECDSA_SHA512,
            CKM.CKM_ECDSA_SHA3_224, CKM.CKM_ECDSA_SHA3_256, CKM.CKM_ECDSA_SHA3_384, CKM.CKM_ECDSA_SHA3_512,
            CKM.CKM_EDDSA);
        Refuse("CNSA 2.0 has no elliptic-curve algorithms; generate ML-DSA-87 or ML-KEM-1024 key pairs instead.",
            "CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN",
            CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM.CKM_DSA_KEY_PAIR_GEN);

        // --- ECDH / X25519 / X448 / DH ---
        Refuse("CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM-1024 replaces ECDH and DH.", MlKem,
            CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE, CKM.CKM_DH_PKCS_DERIVE, CKM.CKM_DH_PKCS_KEY_PAIR_GEN);

        // --- Other post-quantum signatures ---
        Refuse("SLH-DSA (FIPS 205) is not part of CNSA 2.0.", "CKM_ML_DSA (ML-DSA-87), or CKM_HSS / CKM_XMSS for firmware signing",
            CKM.CKM_SLH_DSA, CKM.CKM_SLH_DSA_KEY_PAIR_GEN);
        Refuse("CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87.",
            MlDsa,
            CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_ML_DSA_SHA224, CKM.CKM_HASH_ML_DSA_SHA256, CKM.CKM_HASH_ML_DSA_SHA384,
            CKM.CKM_HASH_ML_DSA_SHA512, CKM.CKM_HASH_ML_DSA_SHA3_224, CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_384,
            CKM.CKM_HASH_ML_DSA_SHA3_512, CKM.CKM_HASH_ML_DSA_SHAKE128, CKM.CKM_HASH_ML_DSA_SHAKE256);
        Refuse("HashSLH-DSA (FIPS 205) is not part of CNSA 2.0.", MlDsa,
            CKM.CKM_HASH_SLH_DSA, CKM.CKM_HASH_SLH_DSA_SHA224, CKM.CKM_HASH_SLH_DSA_SHA256, CKM.CKM_HASH_SLH_DSA_SHA384,
            CKM.CKM_HASH_SLH_DSA_SHA512, CKM.CKM_HASH_SLH_DSA_SHA3_224, CKM.CKM_HASH_SLH_DSA_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_384,
            CKM.CKM_HASH_SLH_DSA_SHA3_512, CKM.CKM_HASH_SLH_DSA_SHAKE128, CKM.CKM_HASH_SLH_DSA_SHAKE256);
        Refuse("CNSA 2.0 allows single-tree XMSS, not the multi-tree XMSS^MT (SP 800-208).", "CKM_XMSS / CKM_XMSS_KEY_PAIR_GEN",
            CKM.CKM_XMSSMT, CKM.CKM_XMSSMT_KEY_PAIR_GEN);

        // --- Symmetric ciphers other than AES-256 GCM / KW / KWP ---
        Refuse("ChaCha20 is not part of CNSA 2.0.", "CKM_AES_GCM with an AES-256 key",
            CKM.CKM_CHACHA20_POLY1305, CKM.CKM_CHACHA20, CKM.CKM_CHACHA20_KEY_GEN);
        Refuse("CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps.",
            AesGcmOrKw,
            CKM.CKM_AES_ECB, CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_CTR, CKM.CKM_AES_CTS, CKM.CKM_AES_OFB,
            CKM.CKM_AES_CFB1, CKM.CKM_AES_CFB8, CKM.CKM_AES_CFB64, CKM.CKM_AES_CFB128, CKM.CKM_AES_XTS, CKM.CKM_AES_XTS_KEY_GEN,
            CKM.CKM_AES_CCM, CKM.CKM_AES_CMAC, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_AES_GMAC);
        Refuse("Its padding is vendor-defined (RFC 5649 on some tokens, KW over PKCS#7 on others), so it is not a known SP 800-38F method.",
            "CKM_AES_KEY_WRAP_KWP or CKM_AES_KEY_WRAP", CKM.CKM_AES_KEY_WRAP_PAD);
        Refuse("DES and TDEA are not part of CNSA 2.0.", "AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys)",
            CKM.CKM_DES_KEY_GEN, CKM.CKM_DES_ECB, CKM.CKM_DES_CBC, CKM.CKM_DES_CBC_PAD,
            CKM.CKM_DES2_KEY_GEN, CKM.CKM_DES3_KEY_GEN, CKM.CKM_DES3_ECB, CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD,
            CKM.CKM_DES3_CMAC, CKM.CKM_DES3_CMAC_GENERAL);

        // --- Hashes and HMACs other than SHA-384 / SHA-512 ---
        Refuse("CNSA 2.0 allows only SHA-384 and SHA-512.", Sha384Or512,
            CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA512_224, CKM.CKM_SHA512_256, CKM.CKM_SHA512_T,
            CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512);
        Refuse("CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those.", HmacSha384Or512,
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA_1_HMAC_GENERAL, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA224_HMAC_GENERAL,
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA256_HMAC_GENERAL,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_224_HMAC_GENERAL, CKM.CKM_SHA512_256_HMAC, CKM.CKM_SHA512_256_HMAC_GENERAL,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_224_HMAC_GENERAL, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_256_HMAC_GENERAL,
            CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_384_HMAC_GENERAL, CKM.CKM_SHA3_512_HMAC, CKM.CKM_SHA3_512_HMAC_GENERAL);
        Refuse("CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those.",
            "CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN",
            CKM.CKM_SHA_1_KEY_GEN, CKM.CKM_SHA224_KEY_GEN, CKM.CKM_SHA256_KEY_GEN,
            CKM.CKM_SHA512_224_KEY_GEN, CKM.CKM_SHA512_256_KEY_GEN,
            CKM.CKM_SHA3_224_KEY_GEN, CKM.CKM_SHA3_256_KEY_GEN, CKM.CKM_SHA3_384_KEY_GEN, CKM.CKM_SHA3_512_KEY_GEN);

        // --- Password-based key derivation ---
        Refuse("CNSA 2.0 has no password-based key derivation.",
            "CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) over a 256-bit secret held on the token",
            CKM.CKM_PKCS5_PBKD2);

        return refused.ToFrozenDictionary();
    }

    // --- Hashes (HashUseRequest) ---

    private static FrozenDictionary<string, AllowedHash> BuildAllowedHashes() => new Dictionary<string, AllowedHash>(StringComparer.Ordinal)
    {
        ["SHA384"] = new(AnyOperation, "CNSA 2.0 SHA-384 (FIPS 180-4)"),
        ["SHA512"] = new(AnyOperation, "CNSA 2.0 SHA-512 (FIPS 180-4)"),
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedHashes()
    {
        var refusal = new DocumentedRefusal("CNSA 2.0 allows only SHA-384 and SHA-512.", "SHA384 or SHA512");
        return new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["MD5"] = refusal,
            ["SHA1"] = refusal,
            ["SHA224"] = refusal,
            ["SHA256"] = refusal,
            ["SHA3-256"] = refusal,
            ["SHA3-384"] = refusal,
            ["SHA3-512"] = refusal,
        }.ToFrozenDictionary(StringComparer.Ordinal);
    }

    // --- EC curves (EcKeyGenerationRequest): none allowed ---

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedCurves()
    {
        var refusal = new DocumentedRefusal(
            "CNSA 2.0 has no elliptic-curve algorithms.",
            "ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys");
        var curves = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal);
#pragma warning disable KLPKCS11007 // the weak curves are what this table documents
        foreach (Pkcs11ECCurve curve in (Pkcs11ECCurve[])[
            Pkcs11ECCurve.NamedCurves.NistP224, Pkcs11ECCurve.NamedCurves.NistP256, Pkcs11ECCurve.NamedCurves.NistP384,
            Pkcs11ECCurve.NamedCurves.NistP521, Pkcs11ECCurve.NamedCurves.Secp256k1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP256r1, Pkcs11ECCurve.NamedCurves.BrainpoolP256t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP320r1, Pkcs11ECCurve.NamedCurves.BrainpoolP320t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP384r1, Pkcs11ECCurve.NamedCurves.BrainpoolP384t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP512r1, Pkcs11ECCurve.NamedCurves.BrainpoolP512t1])
            curves[curve.Oid!] = refusal;
#pragma warning restore KLPKCS11007
        return curves.ToFrozenDictionary(StringComparer.Ordinal);
    }

    // --- Key-agreement KDFs (KeyAgreementKdfRequest): none allowed ---

    private static FrozenDictionary<CKD, DocumentedRefusal> BuildDocumentedRefusedKdfs()
    {
        var refusal = new DocumentedRefusal(
            "CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used.",
            "CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512");
        return new[]
        {
            CKD.CKD_SHA224_KDF, CKD.CKD_SHA256_KDF, CKD.CKD_SHA384_KDF, CKD.CKD_SHA512_KDF,
            CKD.CKD_SHA224_KDF_SP800, CKD.CKD_SHA256_KDF_SP800, CKD.CKD_SHA384_KDF_SP800, CKD.CKD_SHA512_KDF_SP800,
            CKD.CKD_SHA3_224_KDF_SP800, CKD.CKD_SHA3_256_KDF_SP800, CKD.CKD_SHA3_384_KDF_SP800, CKD.CKD_SHA3_512_KDF_SP800,
            CKD.CKD_SHA3_256_KDF, CKD.CKD_SHA3_384_KDF, CKD.CKD_SHA3_512_KDF,
        }.ToFrozenDictionary(k => k, _ => refusal);
    }

    // --- KDF PRFs (documentation only; Cnsa20Wording's PRF checks decide the verdict) ---

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedPrfs()
    {
        var refusal = new DocumentedRefusal("CNSA 2.0 allows only SHA-384 and SHA-512.", "HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF)");
        Dictionary<string, DocumentedRefusal> prfs = new[]
        {
            CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA512_224, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_256_HMAC,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
        }.ToDictionary(p => p.ToString(), _ => refusal, StringComparer.Ordinal);
        prfs[nameof(CKM.CKM_AES_CMAC)] = new DocumentedRefusal(
            "This policy allows only HMAC-SHA-384 and HMAC-SHA-512 as the SP 800-108 PRF.", "HMAC-SHA-384 or HMAC-SHA-512");
        return prfs.ToFrozenDictionary(StringComparer.Ordinal);
    }
}
