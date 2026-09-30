using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

// The SecureOnly catalogue: its allow-lists, rules, and documented deny list.
public sealed partial class SecureOnlyPolicy
{
    private const S Cipher = S.Encrypt | S.Decrypt | S.Wrap | S.Unwrap;
    private const S Signature = S.Sign | S.Verify;

    // A HashUseRequest names the hash a managed-side pre-hash uses; an allowed hash is allowed whichever
    // operation it serves.
    private const S AnyOperation =
        S.Encrypt | S.Decrypt | S.Sign | S.Verify | S.Wrap | S.Unwrap | S.Derive | S.Digest |
        S.GenerateKey | S.GenerateKeyPair | S.Encapsulate | S.Decapsulate;

    /// <summary>
    /// The built-in SecureOnly catalogue. A mechanism, hash, curve, or KDF absent from its
    /// <c>Allowed*</c> tables is refused for every operation.
    /// </summary>
    private static readonly PolicyCatalogue DefaultCatalogue = BuildCatalogue();

    private static PolicyCatalogue BuildCatalogue() => new()
    {
        AllowedMechanisms = BuildAllowedMechanisms(),
        AllowedVendorMechanisms = FrozenDictionary<ulong, MechanismRule>.Empty,
        AllowedHashes = BuildAllowedHashes(),
        AllowedCurves = BuildAllowedCurves(),
        AllowedKdfs = BuildAllowedKdfs(),
        AllowedKeyAgreementKeyTypes = new Dictionary<CKK, string>
        {
            [CKK.CKK_EC] = "ECDH over a Weierstrass curve (SP 800-56A Rev.3); the curve allow-list applies when the key is generated.",
            [CKK.CKK_EC_MONTGOMERY] = "X25519 / X448 (RFC 7748).",
        }.ToFrozenDictionary(),
        Rules = new PolicyRules(
            EvaluateRsaKeyGeneration, EvaluateKeyTemplate, EvaluateKeyMaterialExport,
            RsaKeyGenerationRationale: "RSA key generation requires a modulus of at least 2048 bits (NIST SP 800-131A Rev.2).",
            KeyTemplateRationale: "A key template with CKA_SENSITIVE=false is refused; non-extractable (CKA_EXTRACTABLE=false) stays the default.",
            KeyMaterialExportRationale: "Reading secret key material off the token in the clear is refused; wrap it under a KEK instead."),
        DocumentedRefusedMechanisms = BuildDocumentedRefusedMechanisms(),
        DocumentedRefusedHashes = BuildDocumentedRefusedHashes(),
        DocumentedRefusedCurves = BuildDocumentedRefusedCurves(),
        DocumentedRefusedKdfs = BuildDocumentedRefusedKdfs(),
        DocumentedRefusedKeyAgreementKeyTypes = FrozenDictionary<CKK, DocumentedRefusal>.Empty,
        // Not DocumentedRefusedPrfsTable: that field is declared later in this file, and C# runs static
        // field initializers in textual order — referencing it here (from DefaultCatalogue's own
        // initializer, which appears first) would read it before it is assigned. Building it fresh here
        // is only a cheap dictionary construction and sidesteps the ordering hazard entirely.
        //
        // AllowedKdfPrfs, by contrast, safely reads Prfs.Pbkdf2/Prfs.Sp800108/Prfs.Hkdf (the nested
        // Prfs holder in SecureOnlyPolicy.cs) directly — a nested type's static initializer runs on that
        // type's own first access, independent of this type's field-declaration order; see
        // BuildAllowedKdfPrfs' remarks.
        DocumentedRefusedPrfs = BuildDocumentedRefusedPrfs(),
        AllowedKdfPrfs = BuildAllowedKdfPrfs(),
    };

    // --- Rules (RSA key-generation modulus, key template, key-material export) ---

    private static PolicyDecision EvaluateRsaKeyGeneration(RsaKeyGenerationRequest r) =>
        r.ModulusBits < 2048
            ? PolicyDecision.Deny($"RSA-{r.ModulusBits} is below the NIST SP 800-131A 2048-bit minimum; generate a key of at least 2048 bits.")
            : PolicyDecision.Allow;

    // Only a false CKA_SENSITIVE is refused. A true CKA_EXTRACTABLE is not: an extractable key can still
    // be wrapped — exported encrypted under a KEK — which is the standard way to back up and transport
    // keys, and PKCS#11 requires the attribute for it. The value still never leaves in the clear, which is
    // what CKA_SENSITIVE governs and what this refuses. Non-extractable remains the default: the session's
    // secure key defaults set CKA_EXTRACTABLE to false when the caller says nothing.
    private static PolicyDecision EvaluateKeyTemplate(KeyTemplateRequest r) =>
        r.Attributes.Any(a => a.Type == CKA.CKA_SENSITIVE && !a.GetValueAsBool())
            ? PolicyDecision.Deny("Creating a key with CKA_SENSITIVE=false would create a non-sensitive key whose value can be read off the token.")
            : PolicyDecision.Allow;

    private static PolicyDecision EvaluateKeyMaterialExport(KeyMaterialExportRequest r) =>
        PolicyDecision.Deny(
            $"Reading the {r.Kind} off the token violates the non-extractable-by-default posture. " +
            "Keep the secret on the token (Pkcs11Key.EncapsulateKey / DecapsulateKey / Derive to a sensitive key).");

    // --- Mechanisms ---

    private static FrozenDictionary<CKM, MechanismRule> BuildAllowedMechanisms()
    {
        var rules = new Dictionary<CKM, MechanismRule>();

        // Indexer, not Add: the CKM enum has spec aliases sharing one value (e.g. CKM_ECDSA_KEY_PAIR_GEN
        // == CKM_EC_KEY_PAIR_GEN), and the last write for a value is simply the same rule again.
        void Allow(S ops, string rationale, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new MechanismRule(ops, S.None, null, rationale);
        }
        void AllowChecked(S ops, string rationale, Func<Mechanism, CryptoOperation, PolicyDecision> check, string checkDescription, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms)
                rules[m] = new MechanismRule(ops, S.None, check, rationale) { ParameterCheckDescription = checkDescription };
        }

        // --- AES ---
        Allow(Cipher, "Authenticated encryption (AES-GCM / AES-CCM).", CKM.CKM_AES_GCM, CKM.CKM_AES_CCM);
        Allow(Cipher, "Standard AES key wrapping (RFC 3394 / RFC 5649, SP 800-38F).",
            CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP);
        Allow(Cipher,
            "AES key wrap with vendor-defined padding (RFC 5649 on some tokens, KW over PKCS#7 on others), kept for " +
            "interop with tokens that lack CKM_AES_KEY_WRAP_KWP; see the known limits.",
            CKM.CKM_AES_KEY_WRAP_PAD);
        Allow(Signature, "AES-based MACs secure for variable-length messages (CMAC, GMAC).",
            CKM.CKM_AES_CMAC, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_AES_GMAC);
        Allow(S.GenerateKey, "AES key generation.", CKM.CKM_AES_KEY_GEN);

        // --- ChaCha20 ---
        Allow(Cipher, "Authenticated encryption (RFC 8439 ChaCha20-Poly1305).", CKM.CKM_CHACHA20_POLY1305);
        Allow(S.GenerateKey, "ChaCha20 key generation.", CKM.CKM_CHACHA20_KEY_GEN);

        // --- Digests, HMAC and HMAC keys ---
        Allow(S.Digest, "SHA-2 / SHA-3 digest with at least 128-bit collision resistance.",
            CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512);
        Allow(Signature, "HMAC over SHA-2 / SHA-3 with at least 256-bit output.",
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA256_HMAC_GENERAL, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL,
            CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL,
            CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_256_HMAC_GENERAL, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_384_HMAC_GENERAL,
            CKM.CKM_SHA3_512_HMAC, CKM.CKM_SHA3_512_HMAC_GENERAL);
        Allow(S.GenerateKey, "Generic-secret / HMAC key generation.",
            CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA256_KEY_GEN, CKM.CKM_SHA384_KEY_GEN, CKM.CKM_SHA512_KEY_GEN,
            CKM.CKM_SHA3_256_KEY_GEN, CKM.CKM_SHA3_384_KEY_GEN, CKM.CKM_SHA3_512_KEY_GEN);

        // --- RSA signatures ---
        AllowChecked(Signature, "RSASSA-PSS with a SHA-2 / SHA-3 hash.", CheckHashedPss,
            "parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash",
            CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_SHA3_256_RSA_PKCS_PSS, CKM.CKM_SHA3_384_RSA_PKCS_PSS, CKM.CKM_SHA3_512_RSA_PKCS_PSS);
        AllowChecked(Signature, "RSASSA-PSS over a caller-computed digest.", CheckPss,
            "requires CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash",
            CKM.CKM_RSA_PKCS_PSS);
        Allow(Signature,
            "RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop.",
            CKM.CKM_SHA256_RSA_PKCS, CKM.CKM_SHA384_RSA_PKCS, CKM.CKM_SHA512_RSA_PKCS,
            CKM.CKM_SHA3_256_RSA_PKCS, CKM.CKM_SHA3_384_RSA_PKCS, CKM.CKM_SHA3_512_RSA_PKCS);

        // --- RSA encryption and key generation ---
        AllowChecked(Cipher | S.Encapsulate | S.Decapsulate, "RSAES-OAEP key transport (also as a PKCS#11 v3.2 KEM).", CheckOaep,
            "requires CkmRsaPkcsOaepParams naming SHA-256 or stronger",
            CKM.CKM_RSA_PKCS_OAEP);
        Allow(S.GenerateKeyPair, "RSA key generation (modulus of at least 2048 bits, see the rules).", CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        // --- EC ---
        Allow(Signature, "ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest).",
            CKM.CKM_ECDSA, CKM.CKM_ECDSA_SHA256, CKM.CKM_ECDSA_SHA384, CKM.CKM_ECDSA_SHA512,
            CKM.CKM_ECDSA_SHA3_256, CKM.CKM_ECDSA_SHA3_384, CKM.CKM_ECDSA_SHA3_512);
        Allow(S.GenerateKeyPair, "EC key generation (the curve allow-list applies).", CKM.CKM_EC_KEY_PAIR_GEN);
        AllowChecked(S.Derive | S.Encapsulate | S.Decapsulate,
            "ECDH key agreement (the key-agreement KDF allow-list applies), also as a PKCS#11 v3.2 KEM.",
            KeyAgreementParameterChecks.RequireEcdh1DeriveParams, KeyAgreementParameterChecks.Ecdh1DeriveDescription,
            CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE);
        Allow(Signature, "EdDSA (Ed25519 / Ed448, RFC 8032).", CKM.CKM_EDDSA);
        Allow(S.GenerateKeyPair, "Edwards (Ed25519 / Ed448) and Montgomery (X25519 / X448) key generation.",
            CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);

        // --- Post-quantum (FIPS 203 / 204 / 205) ---
        Allow(S.Encapsulate | S.Decapsulate, "ML-KEM (FIPS 203).", CKM.CKM_ML_KEM);
        Allow(Signature, "ML-DSA (FIPS 204) / SLH-DSA (FIPS 205).", CKM.CKM_ML_DSA, CKM.CKM_SLH_DSA);
        Allow(Signature, "HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits.",
            CKM.CKM_HASH_ML_DSA_SHA256, CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_HASH_ML_DSA_SHA512,
            CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_HASH_ML_DSA_SHA3_512,
            CKM.CKM_HASH_ML_DSA_SHAKE128, CKM.CKM_HASH_ML_DSA_SHAKE256);
        Allow(Signature, "HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits.",
            CKM.CKM_HASH_SLH_DSA_SHA256, CKM.CKM_HASH_SLH_DSA_SHA384, CKM.CKM_HASH_SLH_DSA_SHA512,
            CKM.CKM_HASH_SLH_DSA_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_384, CKM.CKM_HASH_SLH_DSA_SHA3_512,
            CKM.CKM_HASH_SLH_DSA_SHAKE128, CKM.CKM_HASH_SLH_DSA_SHAKE256);
        AllowChecked(Signature, "HashML-DSA (FIPS 204) / HashSLH-DSA (FIPS 205) with a caller-chosen pre-hash.", CheckPqcPreHash,
            "requires CkmHashPqcSignParams naming a pre-hash of at least 256 bits",
            CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_SLH_DSA);
        Allow(S.GenerateKeyPair, "ML-KEM / ML-DSA / SLH-DSA key generation (FIPS 203 / 204 / 205).",
            CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA_KEY_PAIR_GEN);

        // --- KDFs (PRF allow-listed inside each mechanism's parameters, see the KDF PRF checks region) ---
        AllowChecked(S.Derive, "SP 800-108 key derivation.", CheckSp800108Prf,
            "requires CkmSp800108KdfParams naming an allowed PRF (CKM_SHA256/384/512_HMAC, CKM_SHA3_256/384/512_HMAC, or CKM_AES_CMAC)",
            CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF);
        AllowChecked(S.Derive, "HKDF (RFC 5869 / SP 800-56C).", CheckHkdfPrf,
            "requires CkmHkdfParams naming an allowed PRF (CKM_SHA256/384/512 or CKM_SHA3_256/384/512, hash or _HMAC form)",
            CKM.CKM_HKDF_DERIVE);
        Allow(S.GenerateKey, "HKDF salt / key generation.", CKM.CKM_HKDF_KEY_GEN);
        AllowChecked(S.GenerateKey | S.Derive, "PBKDF2 (RFC 8018 / SP 800-132) password-based key derivation.", CheckPbkdf2Prf,
            "requires CkmPkcs5Pbkd2Params naming an allowed PRF (CKP_PKCS5_PBKD2_HMAC_SHA256, _SHA384, _SHA512, or _SHA512_256)",
            CKM.CKM_PKCS5_PBKD2);

        return rules.ToFrozenDictionary();
    }

    /// <summary>
    /// Mechanisms considered and refused, each with its reason and alternative. Documentation only: every
    /// one of them is refused because it is absent from <see cref="BuildAllowedMechanisms"/>.
    /// </summary>
    private static FrozenDictionary<CKM, DocumentedRefusal> BuildDocumentedRefusedMechanisms()
    {
        var refused = new Dictionary<CKM, DocumentedRefusal>();

        // Indexer, not Add: CKM_CAST5_* are the old names of CKM_CAST128_* (identical values).
        void Refuse(string reason, string? alternative, params CKM[] mechanisms)
        {
            var refusal = new DocumentedRefusal(reason, alternative);
            foreach (CKM m in mechanisms) refused[m] = refusal;
        }

        const string AesAead = "CKM_AES_GCM or CKM_AES_CCM";
        const string AesGcm = "CKM_AES_GCM";
        const string Sha256OrStronger = "CKM_SHA256 or stronger";
        const string Sweet32 = "a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks.";

        // --- AES and other block-cipher modes ---
        Refuse(
            "Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks.",
            AesAead,
            CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_CFB1, CKM.CKM_AES_CFB128, CKM.CKM_AES_CFB64,
            CKM.CKM_AES_CFB8, CKM.CKM_AES_CTR, CKM.CKM_AES_CTS, CKM.CKM_AES_OFB);
        Refuse("ECB mode leaks structural information from the plaintext.", AesAead,
            CKM.CKM_AES_ECB, CKM.CKM_ARIA_ECB, CKM.CKM_CAMELLIA_ECB);
        Refuse("AES-XTS provides no integrity protection and is designed for disk-sector encryption, not general-purpose use.",
            AesAead, CKM.CKM_AES_XTS);
        Refuse("CBC-MAC is unsafe for variable-length messages; TDEA is deprecated.", "CKM_AES_CMAC",
            CKM.CKM_AES_MAC, CKM.CKM_AES_MAC_GENERAL, CKM.CKM_DES3_CMAC, CKM.CKM_DES3_CMAC_GENERAL);
        Refuse("Non-standard padding, not RFC 5649.", "CKM_AES_KEY_WRAP_KWP", CKM.CKM_AES_KEY_WRAP_PKCS7);

        // --- Legacy ciphers ---
        Refuse("Blowfish is " + Sweet32, AesGcm,
            CKM.CKM_BLOWFISH_CBC, CKM.CKM_BLOWFISH_CBC_PAD, CKM.CKM_BLOWFISH_KEY_GEN);
        Refuse("CAST is " + Sweet32, AesGcm,
            CKM.CKM_CAST128_CBC, CKM.CKM_CAST128_CBC_PAD, CKM.CKM_CAST128_ECB, CKM.CKM_CAST128_KEY_GEN,
            CKM.CKM_CAST128_MAC, CKM.CKM_CAST128_MAC_GENERAL,
            CKM.CKM_CAST3_CBC, CKM.CKM_CAST3_CBC_PAD, CKM.CKM_CAST3_ECB, CKM.CKM_CAST3_KEY_GEN,
            CKM.CKM_CAST3_MAC, CKM.CKM_CAST3_MAC_GENERAL,
            CKM.CKM_CAST_CBC, CKM.CKM_CAST_CBC_PAD, CKM.CKM_CAST_ECB, CKM.CKM_CAST_KEY_GEN,
            CKM.CKM_CAST_MAC, CKM.CKM_CAST_MAC_GENERAL);
        Refuse("Raw ChaCha20/Salsa20 provide no integrity protection and are malleable.",
            "CKM_CHACHA20_POLY1305 or CKM_AES_GCM", CKM.CKM_CHACHA20, CKM.CKM_SALSA20);
        Refuse("DES and 3DES key generation produces deprecated keys.", "CKM_AES_KEY_GEN",
            CKM.CKM_DES2_KEY_GEN, CKM.CKM_DES3_KEY_GEN, CKM.CKM_DES_KEY_GEN);
        Refuse("DES and 3DES are deprecated.", "AES (CKM_AES_GCM or CKM_AES_CCM)",
            CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD, CKM.CKM_DES3_ECB, CKM.CKM_DES_CBC, CKM.CKM_DES_CBC_PAD, CKM.CKM_DES_ECB);
        Refuse("DES/3DES MAC is weak.", "CKM_AES_CMAC or CKM_SHA256_HMAC",
            CKM.CKM_DES3_MAC, CKM.CKM_DES3_MAC_GENERAL, CKM.CKM_DES_MAC, CKM.CKM_DES_MAC_GENERAL);
        Refuse(
            "This is a legacy 64-bit-block cipher in ECB mode, both leaking structural information from the plaintext and vulnerable to birthday (Sweet32) attacks.",
            AesGcm, CKM.CKM_GOST28147_ECB, CKM.CKM_IDEA_ECB);
        Refuse("RC2 is a deprecated 40/64-bit-key cipher with known weaknesses.", AesGcm,
            CKM.CKM_RC2_CBC, CKM.CKM_RC2_CBC_PAD, CKM.CKM_RC2_ECB, CKM.CKM_RC2_KEY_GEN, CKM.CKM_RC2_MAC, CKM.CKM_RC2_MAC_GENERAL);
        Refuse("RC4 is a broken stream cipher with a biased keystream (prohibited in TLS by RFC 7465).", AesGcm,
            CKM.CKM_RC4, CKM.CKM_RC4_KEY_GEN);
        Refuse("RC5 is " + Sweet32, AesGcm,
            CKM.CKM_RC5_CBC, CKM.CKM_RC5_CBC_PAD, CKM.CKM_RC5_ECB, CKM.CKM_RC5_KEY_GEN, CKM.CKM_RC5_MAC, CKM.CKM_RC5_MAC_GENERAL);
        Refuse("SEED is a legacy regional cipher retained only for Korean-standard interop.", AesGcm,
            CKM.CKM_SEED_CBC, CKM.CKM_SEED_CBC_ENCRYPT_DATA, CKM.CKM_SEED_CBC_PAD, CKM.CKM_SEED_ECB,
            CKM.CKM_SEED_ECB_ENCRYPT_DATA, CKM.CKM_SEED_KEY_GEN, CKM.CKM_SEED_MAC, CKM.CKM_SEED_MAC_GENERAL);
        Refuse("SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses.",
            "CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping)",
            CKM.CKM_SKIPJACK_CBC64, CKM.CKM_SKIPJACK_CFB16, CKM.CKM_SKIPJACK_CFB32, CKM.CKM_SKIPJACK_CFB64,
            CKM.CKM_SKIPJACK_CFB8, CKM.CKM_SKIPJACK_ECB64, CKM.CKM_SKIPJACK_KEY_GEN, CKM.CKM_SKIPJACK_OFB64,
            CKM.CKM_SKIPJACK_PRIVATE_WRAP, CKM.CKM_SKIPJACK_RELAYX, CKM.CKM_SKIPJACK_WRAP);

        // --- Key derivation ---
        Refuse(
            "This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks.",
            null,
            CKM.CKM_CONCATENATE_BASE_AND_DATA, CKM.CKM_CONCATENATE_BASE_AND_KEY, CKM.CKM_CONCATENATE_DATA_AND_BASE,
            CKM.CKM_EXTRACT_KEY_FROM_KEY, CKM.CKM_XOR_BASE_AND_DATA);
        Refuse("DES3 key-derive mechanisms are weak.", "an SP 800-108 KDF (CKM_SP800_108_COUNTER_KDF) or CKM_HKDF_DERIVE on a strong base key",
            CKM.CKM_DES3_CBC_ENCRYPT_DATA, CKM.CKM_DES3_ECB_ENCRYPT_DATA);
        Refuse("Hash-of-key derivation with no salt or label.", "CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF)",
            CKM.CKM_SHA224_KEY_DERIVATION, CKM.CKM_SHA256_KEY_DERIVATION, CKM.CKM_SHA384_KEY_DERIVATION,
            CKM.CKM_SHA512_KEY_DERIVATION, CKM.CKM_SHA512_224_KEY_DERIVATION, CKM.CKM_SHA512_256_KEY_DERIVATION,
            CKM.CKM_SHA512_T_KEY_DERIVATION,
            CKM.CKM_SHA3_224_KEY_DERIVE, CKM.CKM_SHA3_256_KEY_DERIVE, CKM.CKM_SHA3_384_KEY_DERIVE, CKM.CKM_SHA3_512_KEY_DERIVE,
            CKM.CKM_SHAKE_128_KEY_DERIVE, CKM.CKM_SHAKE_256_KEY_DERIVE);
        Refuse("Protocol-specific; IPsec stacks should opt in explicitly.",
            "CryptoPolicy.SecureOnly.WithAllowedMechanism(...) after review",
            CKM.CKM_IKE_PRF_DERIVE, CKM.CKM_IKE1_PRF_DERIVE, CKM.CKM_IKE1_EXTENDED_DERIVE, CKM.CKM_IKE2_PRF_PLUS_DERIVE);

        // --- Broken, deprecated or truncated hashes ---
        Refuse("MD2 is a broken hash function.", Sha256OrStronger,
            CKM.CKM_MD2, CKM.CKM_MD2_HMAC, CKM.CKM_MD2_HMAC_GENERAL, CKM.CKM_MD2_KEY_DERIVATION, CKM.CKM_MD2_RSA_PKCS);
        Refuse("MD5 and SHA-1 are broken hash functions.", Sha256OrStronger, CKM.CKM_MD5, CKM.CKM_SHA_1);
        Refuse("MD5/SHA-1-based HMAC and key derivation rely on broken hash functions.",
            "CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger",
            CKM.CKM_MD5_HMAC, CKM.CKM_MD5_HMAC_GENERAL, CKM.CKM_MD5_KEY_DERIVATION, CKM.CKM_SHA1_KEY_DERIVATION);
        Refuse("MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too).",
            "CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256",
            CKM.CKM_MD5_RSA_PKCS, CKM.CKM_SHA1_RSA_PKCS, CKM.CKM_SHA1_RSA_PKCS_PSS);
        Refuse("SHA-1 is collision-broken and deprecated in signature/MAC contexts.", "CKM_SHA256_HMAC or CKM_ECDSA_SHA256",
            CKM.CKM_ECDSA_SHA1, CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA_1_HMAC_GENERAL);
        Refuse(
            "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware.",
            Sha256OrStronger,
            CKM.CKM_ECDSA_SHA224, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA224_RSA_PKCS, CKM.CKM_SHA224_RSA_PKCS_PSS);
        Refuse("No practical benefit over SHA-256; SHA512_T has a caller-chosen truncation.", Sha256OrStronger,
            CKM.CKM_SHA224, CKM.CKM_SHA3_224, CKM.CKM_SHA512_224, CKM.CKM_SHA512_T);
        Refuse("RIPEMD-128/160 are deprecated hash functions.", Sha256OrStronger,
            CKM.CKM_RIPEMD128, CKM.CKM_RIPEMD128_HMAC, CKM.CKM_RIPEMD128_HMAC_GENERAL, CKM.CKM_RIPEMD128_RSA_PKCS,
            CKM.CKM_RIPEMD160, CKM.CKM_RIPEMD160_HMAC, CKM.CKM_RIPEMD160_HMAC_GENERAL, CKM.CKM_RIPEMD160_RSA_PKCS);
        Refuse("SSLv3 MAC mechanisms are tied to a protocol version prohibited by RFC 7568.", "TLS 1.2+ with CKM_SHA256_HMAC",
            CKM.CKM_SSL3_MD5_MAC, CKM.CKM_SSL3_SHA1_MAC);

        // --- Signatures, RSA padding and key generation ---
        Refuse(
            "DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys.",
            "CKM_ECDSA_SHA256 or CKM_ML_DSA",
            CKM.CKM_DSA, CKM.CKM_DSA_SHA1, CKM.CKM_DSA_SHA224, CKM.CKM_DSA_SHA256, CKM.CKM_DSA_SHA384, CKM.CKM_DSA_SHA512);
        Refuse("DSA signing is refused; its keys have no secure use.", "CKM_EC_KEY_PAIR_GEN or CKM_ML_DSA_KEY_PAIR_GEN",
            CKM.CKM_DSA_KEY_PAIR_GEN);
        Refuse("ISO 9796-2 RSA signing is forgeable (Coron-Naccache-Stern).", "CKM_RSA_PKCS_PSS", CKM.CKM_RSA_9796);
        Refuse("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks.",
            "CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing", CKM.CKM_RSA_PKCS);
        Refuse("Raw RSA (X.509, no padding) is malleable and forgeable.",
            "CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing", CKM.CKM_RSA_X_509);
        Refuse("RSA key generation via ANSI X9.31 was removed from FIPS 186-5.", "CKM_RSA_PKCS_KEY_PAIR_GEN",
            CKM.CKM_RSA_X9_31_KEY_PAIR_GEN);

        return refused.ToFrozenDictionary();
    }

    // --- Hashes (HashUseRequest) ---

    private static FrozenDictionary<string, AllowedHash> BuildAllowedHashes()
    {
        const string Rationale = "SHA-2 / SHA-3 with at least 128-bit collision resistance.";
        return new Dictionary<string, AllowedHash>(StringComparer.Ordinal)
        {
            ["SHA256"] = new(AnyOperation, Rationale),
            ["SHA384"] = new(AnyOperation, Rationale),
            ["SHA512"] = new(AnyOperation, Rationale),
            ["SHA3-256"] = new(AnyOperation, Rationale),
            ["SHA3-384"] = new(AnyOperation, Rationale),
            ["SHA3-512"] = new(AnyOperation, Rationale),
        }.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedHashes() => new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
    {
        ["SHA1"] = new("SHA-1 is collision-broken and deprecated in signature contexts.", "SHA256 or stronger"),
        ["MD5"] = new("MD5 is a broken hash function.", "SHA256 or stronger"),
        ["SHA224"] = new(
            "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware.",
            "SHA256 or stronger"),
    }.ToFrozenDictionary(StringComparer.Ordinal);

    // --- EC curves (EcKeyGenerationRequest) ---

    private static FrozenDictionary<string, string> BuildAllowedCurves()
    {
        var curves = new Dictionary<string, string>(StringComparer.Ordinal);

        void Allow(string rationale, params Pkcs11ECCurve[] allowed)
        {
            foreach (Pkcs11ECCurve curve in allowed) curves[curve.Oid!] = rationale;
        }

        Allow("NIST prime curve with at least 128-bit security (FIPS 186-5 / SP 800-186).",
            Pkcs11ECCurve.NamedCurves.NistP256, Pkcs11ECCurve.NamedCurves.NistP384, Pkcs11ECCurve.NamedCurves.NistP521);
        Allow("SEC 2 Koblitz curve with 128-bit security (Bitcoin / Ethereum interop).", Pkcs11ECCurve.NamedCurves.Secp256k1);
        Allow("RFC 5639 Brainpool curve with at least 128-bit security.",
            Pkcs11ECCurve.NamedCurves.BrainpoolP256r1, Pkcs11ECCurve.NamedCurves.BrainpoolP256t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP320r1, Pkcs11ECCurve.NamedCurves.BrainpoolP320t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP384r1, Pkcs11ECCurve.NamedCurves.BrainpoolP384t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP512r1, Pkcs11ECCurve.NamedCurves.BrainpoolP512t1);

        return curves.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedCurves()
    {
        var curves = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal);
        var weak = new DocumentedRefusal("The curve provides less than 128-bit security.", "NistP256 or stronger");

#pragma warning disable KLPKCS11007 // the weak curves are what this table documents
        foreach (Pkcs11ECCurve curve in (Pkcs11ECCurve[])[
            Pkcs11ECCurve.NamedCurves.NistP192, Pkcs11ECCurve.NamedCurves.NistP224,
            Pkcs11ECCurve.NamedCurves.Secp192k1, Pkcs11ECCurve.NamedCurves.Secp224k1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP160r1, Pkcs11ECCurve.NamedCurves.BrainpoolP160t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP192r1, Pkcs11ECCurve.NamedCurves.BrainpoolP192t1,
            Pkcs11ECCurve.NamedCurves.BrainpoolP224r1, Pkcs11ECCurve.NamedCurves.BrainpoolP224t1])
            curves[curve.Oid!] = weak;
#pragma warning restore KLPKCS11007

        curves[Pkcs11ECCurve.NamedCurves.Sm2.Oid!] = new DocumentedRefusal(
            "SM2 is a regional (Chinese national standard) curve that has not been reviewed for this policy.",
            "NistP256 or stronger");

        return curves.ToFrozenDictionary(StringComparer.Ordinal);
    }

    // --- Key-agreement KDFs (KeyAgreementKdfRequest) ---

    private static FrozenDictionary<CKD, string> BuildAllowedKdfs()
    {
        const string X963 = "ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output.";
        const string OneStep = "SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output.";
        return new Dictionary<CKD, string>
        {
            [CKD.CKD_SHA256_KDF] = X963,
            [CKD.CKD_SHA384_KDF] = X963,
            [CKD.CKD_SHA512_KDF] = X963,
            [CKD.CKD_SHA3_256_KDF] = X963,
            [CKD.CKD_SHA3_384_KDF] = X963,
            [CKD.CKD_SHA3_512_KDF] = X963,
            [CKD.CKD_SHA256_KDF_SP800] = OneStep,
            [CKD.CKD_SHA384_KDF_SP800] = OneStep,
            [CKD.CKD_SHA512_KDF_SP800] = OneStep,
            [CKD.CKD_SHA3_256_KDF_SP800] = OneStep,
            [CKD.CKD_SHA3_384_KDF_SP800] = OneStep,
            [CKD.CKD_SHA3_512_KDF_SP800] = OneStep,
        }.ToFrozenDictionary();
    }

    private static FrozenDictionary<CKD, DocumentedRefusal> BuildDocumentedRefusedKdfs()
    {
        var refused = new Dictionary<CKD, DocumentedRefusal>();

        void Refuse(string reason, string? alternative, params CKD[] kdfs)
        {
            var refusal = new DocumentedRefusal(reason, alternative);
            foreach (CKD k in kdfs) refused[k] = refusal;
        }

        const string Sha256Kdf = "the default CKD_SHA256_KDF or stronger";

        Refuse(
            "CKD_NULL applies no KDF to the ECDH shared secret: the derived AES key becomes the raw x-coordinate " +
            "(or a token-chosen truncation of it), which NIST SP 800-56A Rev. 3 §5.8 forbids.",
            Sha256Kdf, CKD.CKD_NULL);
        Refuse("SHA-1 is collision-broken and deprecated.", Sha256Kdf,
            CKD.CKD_SHA1_KDF, CKD.CKD_SHA1_KDF_ASN1, CKD.CKD_SHA1_KDF_CONCATENATE, CKD.CKD_SHA1_KDF_SP800);
        Refuse("SHA-224 / SHA3-224 offer no practical benefit over SHA-256 on equal-cost hardware.", Sha256Kdf,
            CKD.CKD_SHA224_KDF, CKD.CKD_SHA224_KDF_SP800, CKD.CKD_SHA3_224_KDF, CKD.CKD_SHA3_224_KDF_SP800);
        Refuse("BLAKE2b-based key-agreement KDFs are not NIST SP 800-56C KDFs and have not been reviewed for this policy; BLAKE2b-160 is also below 128-bit collision resistance.",
            Sha256Kdf,
            CKD.CKD_BLAKE2B_160_KDF, CKD.CKD_BLAKE2B_256_KDF, CKD.CKD_BLAKE2B_384_KDF, CKD.CKD_BLAKE2B_512_KDF);
        Refuse("CKD_CPDIVERSIFY_KDF is a CryptoPro (GOST) key-diversification function, not a general-purpose key-agreement KDF.",
            Sha256Kdf, CKD.CKD_CPDIVERSIFY_KDF);

        return refused.ToFrozenDictionary();
    }

    // --- KDF PRFs (documentation only; see the KDF PRF checks region in SecureOnlyPolicy.cs, which
    // decides the verdict, and DocumentedRefusedPrfs' remarks) ---

    /// <summary>
    /// PRFs considered and refused inside PBKDF2 / SP 800-108 / HKDF parameters, keyed by the PRF's own
    /// <c>ToString()</c> (its <c>CKP</c> name for PBKDF2, its <c>CKM</c> name for SP 800-108 / HKDF).
    /// Documentation only: every one of them is refused because it is absent from the allow-lists the
    /// KDF PRF checks (<see cref="CheckPbkdf2Prf"/>, <see cref="CheckSp800108Prf"/>,
    /// <see cref="CheckHkdfPrf"/>) apply.
    /// </summary>
    private static readonly FrozenDictionary<string, DocumentedRefusal> DocumentedRefusedPrfsTable = BuildDocumentedRefusedPrfs();

    private static FrozenDictionary<string, DocumentedRefusal> BuildDocumentedRefusedPrfs()
    {
        const string StrongerPrf = "a SHA-256-or-stronger PRF";
        const string Sha1Reason = "SHA-1 is collision-broken and deprecated.";
        const string Sha224Reason = "SHA-224 offers no practical benefit over SHA-256 on equal-cost hardware.";
        const string Sha512_224Reason = "SHA-512/224's truncated output offers no practical benefit over SHA-256.";
        const string GostReason = "GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy.";

        return new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            [nameof(CKP.CKP_PKCS5_PBKD2_HMAC_SHA1)] = new(Sha1Reason, StrongerPrf),
            [nameof(CKM.CKM_SHA_1_HMAC)] = new(Sha1Reason, StrongerPrf),
            [nameof(CKP.CKP_PKCS5_PBKD2_HMAC_SHA224)] = new(Sha224Reason, StrongerPrf),
            [nameof(CKM.CKM_SHA224_HMAC)] = new(Sha224Reason, StrongerPrf),
            [nameof(CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_224)] = new(Sha512_224Reason, StrongerPrf),
            [nameof(CKM.CKM_SHA512_224_HMAC)] = new(Sha512_224Reason, StrongerPrf),
            [nameof(CKP.CKP_PKCS5_PBKD2_HMAC_GOSTR3411)] = new(GostReason, StrongerPrf),
            [nameof(CKM.CKM_GOSTR3411_HMAC)] = new(GostReason, StrongerPrf),
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
    /// with <see cref="SecureOnlyPolicy"/>'s other fields, so there is no "not yet initialized" state to race.
    /// </summary>
    private static FrozenDictionary<string, FrozenSet<string>> BuildAllowedKdfPrfs() => new Dictionary<string, FrozenSet<string>>(StringComparer.Ordinal)
    {
        ["PBKDF2 (CKM_PKCS5_PBKD2)"] = Prfs.Pbkdf2.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
        ["SP 800-108 (CKM_SP800_108_*_KDF)"] = Prfs.Sp800108.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
        ["HKDF (CKM_HKDF_DERIVE)"] = Prfs.Hkdf.Select(prf => prf.ToString()).ToFrozenSet(StringComparer.Ordinal),
    }.ToFrozenDictionary(StringComparer.Ordinal);
}
