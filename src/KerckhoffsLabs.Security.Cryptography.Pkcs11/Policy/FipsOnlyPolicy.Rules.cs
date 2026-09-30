using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>The FipsOnly catalogue: its allow-lists, rules, and documented deny list.</summary>
internal sealed partial class FipsOnlyPolicy
{
    private const S Cipher = S.Encrypt | S.Decrypt | S.Wrap | S.Unwrap;
    private const S Mac = S.Sign | S.Verify;
    private const S Signature = S.Sign | S.Verify;

    /// <summary>Citation shared by every hash approved under FIPS 180-4 (SHA-2) or FIPS 202 (SHA-3).</summary>
    private const string FipsHashCitation = "FIPS 180-4 / FIPS 202";

    // HashUseRequest carries whatever CryptoOperation the caller is pre-hashing for; a hash approved by
    // FIPS 180-4 / FIPS 202 is approved regardless of which one (verdict parity with the pre-catalogue
    // FipsOnlyPolicy.EvaluateHash, which never consulted the operation for these six hashes at all).
    private const S AnyOperation =
        S.Encrypt | S.Decrypt | S.Sign | S.Verify | S.Wrap | S.Unwrap | S.Derive | S.Digest |
        S.GenerateKey | S.GenerateKeyPair | S.Encapsulate | S.Decapsulate;

    /// <summary>
    /// The catalogue evaluated by <see cref="Evaluate"/>. A mechanism, hash, curve, or KDF absent from
    /// its <c>Allowed*</c> tables is refused for every operation.
    /// </summary>
    internal static readonly PolicyCatalogue Catalogue = BuildCatalogue();

    private static PolicyCatalogue BuildCatalogue() => new()
    {
        AllowedMechanisms = BuildAllowedMechanisms(),
        AllowedVendorMechanisms = FrozenDictionary<ulong, MechanismRule>.Empty,
        AllowedHashes = BuildAllowedHashes(),
        AllowedCurves = BuildAllowedCurves(),
        AllowedKdfs = BuildAllowedKdfs(),
        AllowedKeyAgreementKeyTypes = new Dictionary<CKK, string>
        {
            [CKK.CKK_EC] = "SP 800-56A Rev.3 §5.7.1.2 (ECC CDH over an SP 800-186 prime curve)",
        }.ToFrozenDictionary(),
        Rules = new PolicyRules(
            EvaluateRsaKeyGeneration, EvaluateKeyTemplate, EvaluateKeyMaterialExport,
            RsaKeyGenerationRationale: "RSA key generation requires a modulus of at least 2048 bits (FIPS 186-5 §5.1 / SP 800-131A Rev.2 §3).",
            KeyTemplateRationale: "CSPs must not be output in plaintext; a key template with CKA_SENSITIVE=false is refused (FIPS 140-3, ISO/IEC 19790 §7.9).",
            KeyMaterialExportRationale: "Reading key material off the module in plaintext is not permitted (FIPS 140-3, ISO/IEC 19790 §7.9)."),
        DocumentedRefusedMechanisms = BuildDocumentedRefusedMechanisms(),
        DocumentedRefusedHashes = BuildDocumentedRefusedHashes(),
        DocumentedRefusedCurves = BuildDocumentedRefusedCurves(),
        DocumentedRefusedKdfs = BuildDocumentedRefusedKdfs(),
        DocumentedRefusedKeyAgreementKeyTypes = new Dictionary<CKK, DocumentedRefusal>
        {
            [CKK.CKK_EC_MONTGOMERY] = new(
                "SP 800-56A Rev.3 specifies no X25519/X448 scheme and SP 800-186 lists no Montgomery curves, so key agreement with an existing X25519/X448 key has no approval.",
                "ECDH with a CKK_EC key on a NIST prime curve"),
        }.ToFrozenDictionary(),
        // Not DocumentedRefusedPrfsTable: that field is declared later in this file, and C# runs static
        // field initializers in textual order — referencing it here (from Catalogue's own initializer,
        // which appears first) would read it before it is assigned. Building it fresh here is only a
        // cheap dictionary construction and sidesteps the ordering hazard entirely.
        //
        // AllowedKdfPrfs, by contrast, safely reads Prfs.Pbkdf2/Prfs.Sp800108/Prfs.Hkdf (the nested
        // Prfs holder in FipsOnlyPolicy.cs) directly — a nested type's static initializer runs on that
        // type's own first access, independent of this type's field-declaration order; see
        // BuildAllowedKdfPrfs' remarks.
        DocumentedRefusedPrfs = BuildDocumentedRefusedPrfs(),
        AllowedKdfPrfs = BuildAllowedKdfPrfs(),
    };

    // --- Rules (RSA key-generation modulus, key template, key-material export) ---

    private static PolicyDecision EvaluateRsaKeyGeneration(RsaKeyGenerationRequest r) =>
        r.ModulusBits < 2048
            ? PolicyDecision.Deny($"FIPS 186-5 §5.1 / SP 800-131A Rev.2 §3: RSA-{r.ModulusBits} is below the 2048-bit minimum for key generation.")
            : PolicyDecision.Allow;

    private static PolicyDecision EvaluateKeyTemplate(KeyTemplateRequest r) =>
        r.Attributes.Any(a => a.Type == CKA.CKA_SENSITIVE && !a.GetValueAsBool())
            ? PolicyDecision.Deny("FIPS 140-3 (ISO/IEC 19790 §7.9): CSPs must not be output in plaintext; CKA_SENSITIVE=false is refused.")
            : PolicyDecision.Allow;

    private static PolicyDecision EvaluateKeyMaterialExport(KeyMaterialExportRequest r) =>
        PolicyDecision.Deny($"FIPS 140-3 (ISO/IEC 19790 §7.9): reading the {r.Kind} off the module in plaintext is not permitted.");

    // --- Mechanisms ---

    private static FrozenDictionary<CKM, MechanismRule> BuildAllowedMechanisms()
    {
        var rules = new Dictionary<CKM, MechanismRule>();

        // Indexer, not Add: the CKM enum has spec aliases sharing one value (e.g. CKM_ECDSA_KEY_PAIR_GEN
        // == CKM_EC_KEY_PAIR_GEN), and the last write for a value is simply the same rule again.
        void Approve(S ops, string citation, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new MechanismRule(ops, S.None, null, citation);
        }
        void Legacy(S ops, string citation, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new MechanismRule(S.None, ops, null, citation);
        }
        void ApproveChecked(S ops, string citation, Func<Mechanism, CryptoOperation, PolicyDecision> check, string checkDescription, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms)
                rules[m] = new MechanismRule(ops, S.None, check, citation) { ParameterCheckDescription = checkDescription };
        }

        // --- AES (SP 800-38A and Addendum, 38B, 38C, 38D, 38E, 38F) ---
        // Key wrapping is acceptable only through a method specified or approved in SP 800-38F
        // (SP 800-131A Rev.2 §7, Table 6): KW / KWP, or the CCM / GCM authenticated modes. The
        // confidentiality-only modes and XTS therefore encrypt and decrypt data but never wrap keys.
        Approve(S.Encrypt | S.Decrypt, "SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7)",
            CKM.CKM_AES_ECB, CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_CTR, CKM.CKM_AES_CTS,
            CKM.CKM_AES_OFB, CKM.CKM_AES_CFB8, CKM.CKM_AES_CFB64, CKM.CKM_AES_CFB128, CKM.CKM_AES_CFB1);
        Approve(S.Encrypt | S.Decrypt, "SP 800-38E (storage devices only; key wrapping: SP 800-38F / SP 800-131A Rev.2 §7)",
            CKM.CKM_AES_XTS);
        Approve(Cipher, "SP 800-38D / SP 800-38C / SP 800-38F", CKM.CKM_AES_GCM, CKM.CKM_AES_CCM);
        // Not CKM_AES_KEY_WRAP_PAD: see its documented refusal.
        Approve(Cipher, "SP 800-38F", CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP);
        Approve(Mac, "SP 800-38B / SP 800-38D", CKM.CKM_AES_CMAC, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_AES_GMAC);
        Approve(S.GenerateKey, "SP 800-133 Rev.2", CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_XTS_KEY_GEN, CKM.CKM_GENERIC_SECRET_KEY_GEN);

        // --- TDEA: legacy decryption / unwrapping / CMAC verification only (SP 800-131A Rev.2 Tables 1, 6, 9) ---
        Legacy(S.Decrypt | S.Unwrap, "SP 800-131A Rev.2 §2 / §7 (TDEA encryption and key wrapping disallowed after 2023)",
            CKM.CKM_DES3_ECB, CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD);
        Legacy(S.Verify, "SP 800-131A Rev.2 §10 (TDEA CMAC generation disallowed after 2023)", CKM.CKM_DES3_CMAC, CKM.CKM_DES3_CMAC_GENERAL);

        // --- Hashes (FIPS 180-4, FIPS 202) and HMAC (FIPS 198-1) ---
        // CKM_SHA512_T is absent: FIPS 180-4 §5.3.6 approves SHA-512/t only for t = 224 and t = 256,
        // which have their own mechanisms.
        Approve(S.Digest, FipsHashCitation,
            CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA512_224, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512);
        Approve(Mac, "FIPS 198-1 / SP 800-131A Rev.2 §10",
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA_1_HMAC_GENERAL,
            CKM.CKM_SHA224_HMAC, CKM.CKM_SHA224_HMAC_GENERAL, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA256_HMAC_GENERAL,
            CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_224_HMAC_GENERAL, CKM.CKM_SHA512_256_HMAC, CKM.CKM_SHA512_256_HMAC_GENERAL,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_224_HMAC_GENERAL, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_256_HMAC_GENERAL,
            CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_384_HMAC_GENERAL, CKM.CKM_SHA3_512_HMAC, CKM.CKM_SHA3_512_HMAC_GENERAL);
        Approve(S.GenerateKey, "SP 800-133 Rev.2",
            CKM.CKM_SHA_1_KEY_GEN, CKM.CKM_SHA224_KEY_GEN, CKM.CKM_SHA256_KEY_GEN, CKM.CKM_SHA384_KEY_GEN, CKM.CKM_SHA512_KEY_GEN,
            CKM.CKM_SHA512_224_KEY_GEN, CKM.CKM_SHA512_256_KEY_GEN,
            CKM.CKM_SHA3_224_KEY_GEN, CKM.CKM_SHA3_256_KEY_GEN, CKM.CKM_SHA3_384_KEY_GEN, CKM.CKM_SHA3_512_KEY_GEN);

        // --- RSA (FIPS 186-5, SP 800-56B Rev.2) ---
        Approve(Signature, "FIPS 186-5 §5",
            CKM.CKM_SHA224_RSA_PKCS, CKM.CKM_SHA256_RSA_PKCS, CKM.CKM_SHA384_RSA_PKCS, CKM.CKM_SHA512_RSA_PKCS,
            CKM.CKM_SHA3_224_RSA_PKCS, CKM.CKM_SHA3_256_RSA_PKCS, CKM.CKM_SHA3_384_RSA_PKCS, CKM.CKM_SHA3_512_RSA_PKCS);
        foreach (CKM m in (CKM[])[
            CKM.CKM_SHA224_RSA_PKCS_PSS, CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_SHA3_224_RSA_PKCS_PSS, CKM.CKM_SHA3_256_RSA_PKCS_PSS, CKM.CKM_SHA3_384_RSA_PKCS_PSS, CKM.CKM_SHA3_512_RSA_PKCS_PSS])
            rules[m] = new MechanismRule(Signature, S.None, CheckHashedPss, "FIPS 186-5 §5.4") { ParameterCheckDescription = "the MGF/parameter hash, when given, must be an approved hash" };
        Legacy(S.Verify, "SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed)", CKM.CKM_SHA1_RSA_PKCS);
        rules[CKM.CKM_SHA1_RSA_PKCS_PSS] = new MechanismRule(S.None, S.Verify, CheckHashedPss,
            "SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed)");
        rules[CKM.CKM_RSA_PKCS_PSS] = new MechanismRule(Signature, S.None, CheckPss, "FIPS 186-5 §5.4")
        {
            ParameterCheckDescription = "requires CkmRsaPkcsPssParams naming an approved hash, with a salt no longer than that hash",
        };
        // Raw CKM_RSA_PKCS: RSASSA-PKCS1-v1_5 over a caller-built DigestInfo is approved (FIPS 186-5 §5.4)
        // for Sign/Verify. PKCS#1 v1.5 key transport (Encrypt/Decrypt/Wrap/Unwrap) is disallowed after
        // 2023 (SP 800-131A Rev.2 §6, Table 5; FIPS 140-3 IG D.G grants no legacy-use unwrapping for it).
        // The rationale carries that citation, since an allowed entry's operation denial quotes it.
        rules[CKM.CKM_RSA_PKCS] = new MechanismRule(Signature, S.None, null,
            "FIPS 186-5 §5.4 (signatures only: SP 800-131A Rev.2 §6 / Table 5 disallows PKCS#1 v1.5 key transport after 2023; use CKM_RSA_PKCS_OAEP)");
        rules[CKM.CKM_RSA_PKCS_OAEP] = new MechanismRule(Cipher, S.None, CheckOaep, "SP 800-56B Rev.2")
        {
            ParameterCheckDescription = "requires CkmRsaPkcsOaepParams naming an approved hash",
        };
        Approve(S.GenerateKeyPair, "FIPS 186-5 §A.1", CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        // --- DSA: verification of existing signatures only (FIPS 186-5 §4) ---
        Legacy(S.Verify, "FIPS 186-5 §4 (DSA signature generation no longer approved)",
            CKM.CKM_DSA, CKM.CKM_DSA_SHA1, CKM.CKM_DSA_SHA224, CKM.CKM_DSA_SHA256, CKM.CKM_DSA_SHA384, CKM.CKM_DSA_SHA512,
            CKM.CKM_DSA_SHA3_224, CKM.CKM_DSA_SHA3_256, CKM.CKM_DSA_SHA3_384, CKM.CKM_DSA_SHA3_512);

        // --- ECDSA / EdDSA / ECDH (FIPS 186-5, SP 800-186, SP 800-56A Rev.3) ---
        Approve(Signature, "FIPS 186-5 §6",
            CKM.CKM_ECDSA, CKM.CKM_ECDSA_SHA224, CKM.CKM_ECDSA_SHA256, CKM.CKM_ECDSA_SHA384, CKM.CKM_ECDSA_SHA512,
            CKM.CKM_ECDSA_SHA3_224, CKM.CKM_ECDSA_SHA3_256, CKM.CKM_ECDSA_SHA3_384, CKM.CKM_ECDSA_SHA3_512);
        Legacy(S.Verify, "SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed)", CKM.CKM_ECDSA_SHA1);
        Approve(Signature, "FIPS 186-5 §7", CKM.CKM_EDDSA);
        Approve(S.GenerateKeyPair, "FIPS 186-5 §A.2 / SP 800-186", CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);
        ApproveChecked(S.Derive, "SP 800-56A Rev.3",
            KeyAgreementParameterChecks.RequireEcdh1DeriveParams, KeyAgreementParameterChecks.Ecdh1DeriveDescription,
            CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE);

        // --- KDFs (SP 800-108r1, SP 800-56C Rev.2, SP 800-132; PRF allow-listed inside each
        // mechanism's parameters, see the KDF PRF checks region) ---
        ApproveChecked(S.Derive, "SP 800-108r1", CheckSp800108Prf,
            "requires CkmSp800108KdfParams naming an approved PRF (HMAC over an approved hash, or AES-CMAC)",
            CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF);
        ApproveChecked(S.Derive, "SP 800-56C Rev.2", CheckHkdfPrf,
            "requires CkmHkdfParams naming an approved PRF (an approved hash, hash or _HMAC form)",
            CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA);
        Approve(S.GenerateKey, "SP 800-56C Rev.2", CKM.CKM_HKDF_KEY_GEN);
        ApproveChecked(S.GenerateKey | S.Derive, "SP 800-132", CheckPbkdf2Prf,
            "requires CkmPkcs5Pbkd2Params naming an approved PRF (HMAC-SHA-1/224/256/384/512/512-224/512-256)",
            CKM.CKM_PKCS5_PBKD2);

        // --- Post-quantum (FIPS 203 / 204 / 205) ---
        // Pre-hash variants over SHA-224 / SHA3-224 are absent: FIPS 204 §5.4 and FIPS 205 §10 require the
        // pre-hash to give at least 128-bit collision strength (the smallest parameter sets' level). See
        // the documented refusals below.
        Approve(S.Encapsulate | S.Decapsulate, "FIPS 203", CKM.CKM_ML_KEM);
        Approve(Signature, "FIPS 204",
            CKM.CKM_ML_DSA, CKM.CKM_HASH_ML_DSA_SHA256,
            CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_HASH_ML_DSA_SHA512,
            CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_HASH_ML_DSA_SHA3_512,
            CKM.CKM_HASH_ML_DSA_SHAKE128, CKM.CKM_HASH_ML_DSA_SHAKE256);
        Approve(Signature, "FIPS 205",
            CKM.CKM_SLH_DSA, CKM.CKM_HASH_SLH_DSA_SHA256,
            CKM.CKM_HASH_SLH_DSA_SHA384, CKM.CKM_HASH_SLH_DSA_SHA512,
            CKM.CKM_HASH_SLH_DSA_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_384, CKM.CKM_HASH_SLH_DSA_SHA3_512,
            CKM.CKM_HASH_SLH_DSA_SHAKE128, CKM.CKM_HASH_SLH_DSA_SHAKE256);
        // The generic pre-hash mechanisms take the hash in CkmHashPqcSignParams; it is checked the same way.
        rules[CKM.CKM_HASH_ML_DSA] = new MechanismRule(Signature, S.None, CheckPqcPreHash, "FIPS 204 §5.4")
        {
            ParameterCheckDescription = "requires CkmHashPqcSignParams naming a pre-hash of at least 128-bit collision strength",
        };
        rules[CKM.CKM_HASH_SLH_DSA] = new MechanismRule(Signature, S.None, CheckPqcPreHash, "FIPS 205 §10")
        {
            ParameterCheckDescription = "requires CkmHashPqcSignParams naming a pre-hash of at least 128-bit collision strength",
        };
        Approve(S.GenerateKeyPair, "FIPS 203 / 204 / 205",
            CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA_KEY_PAIR_GEN);

        return rules.ToFrozenDictionary();
    }

    /// <summary>The mechanisms considered and refused, each with the source that excludes it.</summary>
    private static FrozenDictionary<CKM, DocumentedRefusal> BuildDocumentedRefusedMechanisms()
    {
        var refused = new Dictionary<CKM, DocumentedRefusal>();

        void Refuse(string reason, string? alternative, params CKM[] mechanisms)
        {
            var refusal = new DocumentedRefusal(reason, alternative);
            foreach (CKM m in mechanisms) refused[m] = refusal;
        }

        Refuse(
            "FIPS 186-5 withdrew Appendix E; RSA key generation via ANSI X9.31 is no longer an approved method.",
            "CKM_RSA_PKCS_KEY_PAIR_GEN",
            CKM.CKM_RSA_X9_31_KEY_PAIR_GEN);
        Refuse(
            "Not on the SP 800-140C Rev.2 CMVP-approved algorithm list; ChaCha20-Poly1305 has no FIPS 140-3 validation entry.",
            "CKM_AES_GCM",
            CKM.CKM_CHACHA20_POLY1305, CKM.CKM_CHACHA20);
        Refuse(
            "Its padding is vendor-defined: some tokens implement RFC 5649 (SP 800-38F KWP), others KW over " +
            "PKCS#7-padded input, which is not an SP 800-38F method. Whether a given token's wrap is approved " +
            "cannot be told from the mechanism, so it is not approved.",
            "CKM_AES_KEY_WRAP_KWP (RFC 5649) or CKM_AES_KEY_WRAP",
            CKM.CKM_AES_KEY_WRAP_PAD);
        Refuse(
            "SP 800-186 lists no Montgomery curves; X25519/X448 key generation has no FIPS 186-5 / SP 800-186 approval.",
            "CKM_EC_KEY_PAIR_GEN (a NIST prime curve) or CKM_EC_EDWARDS_KEY_PAIR_GEN",
            CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        Refuse(
            "FIPS 180-4 §5.3.6 approves SHA-512/t only for t = 224 and t = 256, which have their own mechanisms; " +
            "a caller-chosen truncation has no approval.",
            "CKM_SHA512_224 or CKM_SHA512_256",
            CKM.CKM_SHA512_T);
        Refuse(
            "FIPS 204 §5.4 / FIPS 205 §10 require the pre-hash to give at least 128-bit collision strength; " +
            "SHA-224 / SHA3-224 give only ~112 bits.",
            "the SHA-256/384/512 or SHA3-256/384/512 pre-hash variants",
            CKM.CKM_HASH_ML_DSA_SHA224, CKM.CKM_HASH_ML_DSA_SHA3_224,
            CKM.CKM_HASH_SLH_DSA_SHA224, CKM.CKM_HASH_SLH_DSA_SHA3_224);

        // --- Ciphers with no FIPS 140-3 CMVP-approved algorithm entry (SP 800-140C Rev.2) ---
        const string NotCmvpApproved = "Not on the SP 800-140C Rev.2 CMVP-approved algorithm list.";
        const string AesCbcGcmOrCcm = "CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM";

        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_DES_KEY_GEN, CKM.CKM_DES_ECB, CKM.CKM_DES_CBC, CKM.CKM_DES_CBC_PAD,
            CKM.CKM_DES_MAC, CKM.CKM_DES_MAC_GENERAL,
            CKM.CKM_DES_OFB64, CKM.CKM_DES_OFB8, CKM.CKM_DES_CFB64, CKM.CKM_DES_CFB8);
        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_CAST_KEY_GEN, CKM.CKM_CAST_ECB, CKM.CKM_CAST_CBC, CKM.CKM_CAST_MAC, CKM.CKM_CAST_MAC_GENERAL, CKM.CKM_CAST_CBC_PAD,
            CKM.CKM_CAST3_KEY_GEN, CKM.CKM_CAST3_ECB, CKM.CKM_CAST3_CBC, CKM.CKM_CAST3_MAC, CKM.CKM_CAST3_MAC_GENERAL, CKM.CKM_CAST3_CBC_PAD,
            CKM.CKM_CAST5_KEY_GEN, CKM.CKM_CAST5_ECB, CKM.CKM_CAST5_CBC, CKM.CKM_CAST5_MAC, CKM.CKM_CAST5_MAC_GENERAL, CKM.CKM_CAST5_CBC_PAD);
        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_RC2_KEY_GEN, CKM.CKM_RC2_ECB, CKM.CKM_RC2_CBC, CKM.CKM_RC2_MAC, CKM.CKM_RC2_MAC_GENERAL, CKM.CKM_RC2_CBC_PAD,
            CKM.CKM_RC4_KEY_GEN, CKM.CKM_RC4,
            CKM.CKM_RC5_KEY_GEN, CKM.CKM_RC5_ECB, CKM.CKM_RC5_CBC, CKM.CKM_RC5_MAC, CKM.CKM_RC5_MAC_GENERAL, CKM.CKM_RC5_CBC_PAD);
        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_BLOWFISH_KEY_GEN, CKM.CKM_BLOWFISH_CBC, CKM.CKM_BLOWFISH_CBC_PAD);
        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_IDEA_KEY_GEN, CKM.CKM_IDEA_ECB, CKM.CKM_IDEA_CBC, CKM.CKM_IDEA_MAC, CKM.CKM_IDEA_MAC_GENERAL, CKM.CKM_IDEA_CBC_PAD);
        Refuse(NotCmvpApproved, AesCbcGcmOrCcm,
            CKM.CKM_SEED_KEY_GEN, CKM.CKM_SEED_ECB, CKM.CKM_SEED_CBC, CKM.CKM_SEED_MAC, CKM.CKM_SEED_MAC_GENERAL, CKM.CKM_SEED_CBC_PAD);
        Refuse("Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list.",
            "CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM",
            CKM.CKM_SKIPJACK_KEY_GEN, CKM.CKM_SKIPJACK_ECB64, CKM.CKM_SKIPJACK_CBC64,
            CKM.CKM_SKIPJACK_OFB64, CKM.CKM_SKIPJACK_CFB64, CKM.CKM_SKIPJACK_CFB32, CKM.CKM_SKIPJACK_CFB16, CKM.CKM_SKIPJACK_CFB8,
            CKM.CKM_SKIPJACK_WRAP, CKM.CKM_SKIPJACK_PRIVATE_WRAP, CKM.CKM_SKIPJACK_RELAYX);
        Refuse("GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list.",
            "an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash",
            CKM.CKM_GOSTR3410_KEY_PAIR_GEN, CKM.CKM_GOSTR3410, CKM.CKM_GOSTR3410_WITH_GOSTR3411,
            CKM.CKM_GOSTR3410_KEY_WRAP, CKM.CKM_GOSTR3410_DERIVE, CKM.CKM_GOSTR3411, CKM.CKM_GOSTR3411_HMAC,
            CKM.CKM_GOST28147_KEY_GEN, CKM.CKM_GOST28147_ECB, CKM.CKM_GOST28147, CKM.CKM_GOST28147_MAC, CKM.CKM_GOST28147_KEY_WRAP);

        // --- Hashes with no FIPS 180-4 / FIPS 202 approval ---
        Refuse("Not defined by FIPS 180-4 or FIPS 202; MD2 and MD5 are cryptographically broken.",
            "CKM_SHA256 or stronger",
            CKM.CKM_MD2, CKM.CKM_MD5, CKM.CKM_RIPEMD128, CKM.CKM_RIPEMD160);

        return refused.ToFrozenDictionary();
    }

    // --- Hashes (HashUseRequest) ---

    private static FrozenDictionary<string, AllowedHash> BuildAllowedHashes() => new Dictionary<string, AllowedHash>(StringComparer.Ordinal)
    {
        ["SHA256"] = new(AnyOperation, FipsHashCitation),
        ["SHA384"] = new(AnyOperation, FipsHashCitation),
        ["SHA512"] = new(AnyOperation, FipsHashCitation),
        ["SHA3-256"] = new(AnyOperation, FipsHashCitation),
        ["SHA3-384"] = new(AnyOperation, FipsHashCitation),
        ["SHA3-512"] = new(AnyOperation, FipsHashCitation),
        // Legacy use: verifying an old signature only (SP 800-131A Rev.2 §9); any other operation is
        // refused with this rationale quoted.
        ["SHA1"] = new(S.Verify, "SP 800-131A Rev.2 §9 (legacy-use verification only; SHA-1 signature generation is no longer approved)"),
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedHashes() => new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
    {
        ["MD5"] = new("Not defined by FIPS 180-4 or FIPS 202; MD5 is cryptographically broken.", "SHA256"),
    }.ToFrozenDictionary(StringComparer.Ordinal);

    // --- EC curves (EcKeyGenerationRequest) ---

    private static FrozenDictionary<string, string> BuildAllowedCurves()
    {
        var curves = new Dictionary<string, string>(StringComparer.Ordinal);
        const string Rationale = "SP 800-186 §3.2.1.2 / SP 800-131A Rev.2 Table 2 (len(n) >= 224 acceptable)";

        // P-224 is below SecureOnly's 128-bit baseline but approved here: SP 800-186 §3.2.1.2 and
        // SP 800-131A Rev.2 Table 2 (len(n) >= 224 is acceptable).
#pragma warning disable KLPKCS11007
        curves[Pkcs11ECCurve.NamedCurves.NistP224.Oid!] = Rationale;
#pragma warning restore KLPKCS11007
        curves[Pkcs11ECCurve.NamedCurves.NistP256.Oid!] = Rationale;
        curves[Pkcs11ECCurve.NamedCurves.NistP384.Oid!] = Rationale;
        curves[Pkcs11ECCurve.NamedCurves.NistP521.Oid!] = Rationale;

        return curves.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedCurves()
    {
        var curves = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal);
        var refusal = new DocumentedRefusal(
            "SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves.",
            "NistP256, NistP384, or NistP521");

        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP256r1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP256t1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP320r1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP320t1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP384r1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP384t1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP512r1.Oid!] = refusal;
        curves[Pkcs11ECCurve.NamedCurves.BrainpoolP512t1.Oid!] = refusal;

        return curves.ToFrozenDictionary(StringComparer.Ordinal);
    }

    // --- Key-agreement KDFs (KeyAgreementKdfRequest) ---

    /// <summary>
    /// ANSI X9.63 KDFs (<c>CKD_SHA*_KDF</c>) are approved by SP 800-135 Rev.1 §5.1 only with a FIPS 180
    /// hash, so their SHA-3 variants are documented-refused below; the SP 800-56C one-step KDFs
    /// (<c>*_KDF_SP800</c>) take SHA-2 or SHA-3. SHA-1 variants are refused by design even where a
    /// publication tolerates them.
    /// </summary>
    private static FrozenDictionary<CKD, string> BuildAllowedKdfs()
    {
        const string AnsiX963Kdf = "SP 800-135 Rev.1 §5.1 (ANSI X9.63 KDF over an approved FIPS 180 hash)";
        const string OneStepKdf = "SP 800-56C Rev.2 (one-step KDF)";

        return new Dictionary<CKD, string>
        {
            [CKD.CKD_SHA224_KDF] = AnsiX963Kdf,
            [CKD.CKD_SHA256_KDF] = AnsiX963Kdf,
            [CKD.CKD_SHA384_KDF] = AnsiX963Kdf,
            [CKD.CKD_SHA512_KDF] = AnsiX963Kdf,
            [CKD.CKD_SHA224_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA256_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA384_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA512_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA3_224_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA3_256_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA3_384_KDF_SP800] = OneStepKdf,
            [CKD.CKD_SHA3_512_KDF_SP800] = OneStepKdf,
        }.ToFrozenDictionary();
    }

    private static FrozenDictionary<CKD, DocumentedRefusal> BuildDocumentedRefusedKdfs()
    {
        const string AnsiX963Sha3NotDefined =
            "SP 800-135 Rev.1 §5.1 approves the ANSI X9.63 KDF only with a FIPS 180 hash; no SHA-3 variant is defined.";

        return new Dictionary<CKD, DocumentedRefusal>
        {
            [CKD.CKD_SHA3_224_KDF] = new(AnsiX963Sha3NotDefined, "CKD_SHA3_224_KDF_SP800"),
            [CKD.CKD_SHA3_256_KDF] = new(AnsiX963Sha3NotDefined, "CKD_SHA3_256_KDF_SP800"),
            [CKD.CKD_SHA3_384_KDF] = new(AnsiX963Sha3NotDefined, "CKD_SHA3_384_KDF_SP800"),
            [CKD.CKD_SHA3_512_KDF] = new(AnsiX963Sha3NotDefined, "CKD_SHA3_512_KDF_SP800"),
        }.ToFrozenDictionary();
    }

    // --- KDF PRFs (documentation only; see the KDF PRF checks region in FipsOnlyPolicy.cs, which
    // decides the verdict, and DocumentedRefusedPrfs' remarks) ---

    /// <summary>
    /// PRFs considered and refused inside PBKDF2 / SP 800-108 / HKDF parameters, keyed by the PRF's own
    /// <c>ToString()</c> (its <c>CKP</c> name for PBKDF2, its <c>CKM</c> name for SP 800-108 / HKDF).
    /// Documentation only: every one of them is refused because it is absent from the approved sets the
    /// KDF PRF checks (<see cref="CheckPbkdf2Prf"/>, <see cref="CheckSp800108Prf"/>,
    /// <see cref="CheckHkdfPrf"/>) apply.
    /// </summary>
    private static readonly FrozenDictionary<string, DocumentedRefusal> DocumentedRefusedPrfsTable = BuildDocumentedRefusedPrfs();

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedPrfs()
    {
        const string GostReason = "GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy.";
        const string ApprovedPrf = "an approved PRF (HMAC over an approved hash, or AES-CMAC where the mechanism allows it)";

        return new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            [nameof(CKP.CKP_PKCS5_PBKD2_HMAC_GOSTR3411)] = new(GostReason, ApprovedPrf),
            [nameof(CKM.CKM_GOSTR3411_HMAC)] = new(GostReason, ApprovedPrf),
        }.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>
    /// Builds <see cref="PolicyCatalogue.AllowedKdfPrfs"/> for the generated catalogue documentation
    /// — derived directly from <see cref="Prfs.Pbkdf2"/>, <see cref="Prfs.Sp800108"/>
    /// and <see cref="Prfs.Hkdf"/>, the same sets <see cref="CheckPbkdf2Prf"/>, <see cref="CheckSp800108Prf"/>
    /// and <see cref="CheckHkdfPrf"/> decide the verdict from — one source of truth, so the documentation
    /// cannot drift from what is actually enforced. Safe to call from <see cref="BuildCatalogue"/>'s own
    /// field initializer despite the static-field-ordering hazard documented on <see cref="Prfs"/>: a
    /// nested type's static initializer runs on that type's own first access here, not in textual order
    /// with <see cref="FipsOnlyPolicy"/>'s other fields, so there is no "not yet initialized" state to race.
    /// </summary>
    private static FrozenDictionary<string, FrozenSet<string>> BuildAllowedKdfPrfs() => new Dictionary<string, FrozenSet<string>>(StringComparer.Ordinal)
    {
        ["PBKDF2 (CKM_PKCS5_PBKD2)"] = Prfs.Pbkdf2.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
        ["SP 800-108 (CKM_SP800_108_*_KDF)"] = Prfs.Sp800108.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
        ["HKDF (CKM_HKDF_DERIVE / CKM_HKDF_DATA)"] = Prfs.Hkdf.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
    }.ToFrozenDictionary(StringComparer.Ordinal);
}
