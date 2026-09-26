using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperationSet;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

internal sealed partial class FipsOnlyPolicy
{
    private const S Cipher = S.Encrypt | S.Decrypt | S.Wrap | S.Unwrap;
    private const S Mac = S.Sign | S.Verify;
    private const S Signature = S.Sign | S.Verify;

    /// <summary>The allow-list. A mechanism absent from this table is refused for every operation.</summary>
    private static readonly FrozenDictionary<CKM, FipsRule> Rules = BuildRules();

    private static FrozenDictionary<CKM, FipsRule> BuildRules()
    {
        var rules = new Dictionary<CKM, FipsRule>();

        // Indexer, not Add: the CKM enum has spec aliases sharing one value (e.g. CKM_ECDSA_KEY_PAIR_GEN
        // == CKM_EC_KEY_PAIR_GEN), and the last write for a value is simply the same rule again.
        void Approve(S ops, string citation, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new FipsRule(ops, S.None, null, citation);
        }
        void Legacy(S ops, string citation, params CKM[] mechanisms)
        {
            foreach (CKM m in mechanisms) rules[m] = new FipsRule(S.None, ops, null, citation);
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
        // CKM_AES_KEY_WRAP_PAD is vendor-dependent: some tokens implement it as RFC 5649 / SP 800-38F KWP,
        // others as KW over PKCS#7-padded input, which is not an SP 800-38F method. It stays approved
        // because the common implementations are KWP; the public FipsOnly docs flag the caveat and point
        // callers to CKM_AES_KEY_WRAP_KWP where the token has it.
        Approve(Cipher, "SP 800-38F", CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_PAD, CKM.CKM_AES_KEY_WRAP_KWP);
        Approve(Mac, "SP 800-38B / SP 800-38D", CKM.CKM_AES_CMAC, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_AES_GMAC);
        Approve(S.GenerateKey, "SP 800-133 Rev.2", CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_XTS_KEY_GEN, CKM.CKM_GENERIC_SECRET_KEY_GEN);

        // --- TDEA: legacy decryption / unwrapping / CMAC verification only (SP 800-131A Rev.2 Tables 1, 6, 9) ---
        Legacy(S.Decrypt | S.Unwrap, "SP 800-131A Rev.2 §2 / §7 (TDEA encryption and key wrapping disallowed after 2023)",
            CKM.CKM_DES3_ECB, CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD);
        Legacy(S.Verify, "SP 800-131A Rev.2 §10 (TDEA CMAC generation disallowed after 2023)", CKM.CKM_DES3_CMAC, CKM.CKM_DES3_CMAC_GENERAL);

        // --- Hashes (FIPS 180-4, FIPS 202) and HMAC (FIPS 198-1) ---
        // CKM_SHA512_T is absent: FIPS 180-4 §5.3.6 approves SHA-512/t only for t = 224 and t = 256,
        // which have their own mechanisms.
        Approve(S.Digest, "FIPS 180-4 / FIPS 202",
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
            rules[m] = new FipsRule(Signature, S.None, CheckHashedPss, "FIPS 186-5 §5.4");
        Legacy(S.Verify, "SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed)", CKM.CKM_SHA1_RSA_PKCS);
        rules[CKM.CKM_SHA1_RSA_PKCS_PSS] = new FipsRule(S.None, S.Verify, CheckHashedPss,
            "SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed)");
        rules[CKM.CKM_RSA_PKCS_PSS] = new FipsRule(Signature, S.None, CheckPss, "FIPS 186-5 §5.4");
        // Raw CKM_RSA_PKCS: RSASSA-PKCS1-v1_5 over a caller-built DigestInfo is approved (FIPS 186-5 §5.4).
        // PKCS#1 v1.5 key transport is disallowed after 2023 for encryption and decryption alike
        // (SP 800-131A Rev.2 §6, Table 5; FIPS 140-3 IG D.G grants no legacy-use unwrapping for it).
        rules[CKM.CKM_RSA_PKCS] = new FipsRule(Signature, S.None, null,
            "SP 800-131A Rev.2 §6 (PKCS#1 v1.5 key transport disallowed)");
        rules[CKM.CKM_RSA_PKCS_OAEP] = new FipsRule(Cipher, S.None, CheckOaep, "SP 800-56B Rev.2");
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
        Approve(S.Derive, "SP 800-56A Rev.3", CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE);

        // --- KDFs (SP 800-108r1, SP 800-56C Rev.2, SP 800-132) ---
        Approve(S.Derive, "SP 800-108r1",
            CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF);
        Approve(S.Derive, "SP 800-56C Rev.2", CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA);
        Approve(S.GenerateKey, "SP 800-56C Rev.2", CKM.CKM_HKDF_KEY_GEN);
        Approve(S.GenerateKey | S.Derive, "SP 800-132", CKM.CKM_PKCS5_PBKD2);

        // --- Post-quantum (FIPS 203 / 204 / 205) ---
        // Pre-hash variants over SHA-224 / SHA3-224 are absent: FIPS 204 §5.4 and FIPS 205 §10 require the
        // pre-hash to give at least 128-bit collision strength (the smallest parameter sets' level).
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
        rules[CKM.CKM_HASH_ML_DSA] = new FipsRule(Signature, S.None, CheckPqcPreHash, "FIPS 204 §5.4");
        rules[CKM.CKM_HASH_SLH_DSA] = new FipsRule(Signature, S.None, CheckPqcPreHash, "FIPS 205 §10");
        Approve(S.GenerateKeyPair, "FIPS 203 / 204 / 205",
            CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA_KEY_PAIR_GEN);

        return rules.ToFrozenDictionary();
    }
}
