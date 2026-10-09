using System.Collections.Immutable;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.SecurityAnalyzers;

/// <summary>
/// The mechanism/mode names <see cref="InsecureMechanismAnalyzer"/> reports on (KLPKCS11009).
/// </summary>
/// <remarks>
/// Deliberately free of any Roslyn type: the library's test project reads these sets to pin them
/// against <c>SecureOnlyPolicy</c>'s documented refusals, and touching a type
/// that derived from <c>DiagnosticAnalyzer</c> would drag the compiler assemblies into the test host.
/// The analyzer cannot simply reference the library's <c>CKM</c> enum — it targets netstandard2.0 and
/// referencing the library would be a cycle — so this list is a transcription, and the parity tests
/// exist to make sure it never drifts from the guard.
/// </remarks>
public static class InsecureMechanismData
{
    /// <summary>
    /// The default <c>SecureOnly</c> policy's documented refusals, minus the RSA-encryption pair covered
    /// by KLPKCS11008.
    /// </summary>
    /// <remarks>
    /// Only the documented refusals — mechanisms reviewed and rejected with a reason — are listed. The
    /// policy also denies every mechanism it has not reviewed (vendor mechanisms included); those carry
    /// no warning here, since "not reviewed" is not a finding about the mechanism.
    /// <para>
    /// Deliberately excludes <c>CKM_RSA_PKCS_OAEP</c>: <c>SecureOnlyPolicy</c> denies it only without
    /// <c>CkmRsaPkcsOaepParams</c> or with a hash outside its allowed set (SHA-256/384/512, SHA-512/256,
    /// SHA3-256/384/512) — a mechanism-*parameter* condition no static analyzer here can evaluate (the
    /// type alone is used just as often with a safe hash and must not be flagged). The runtime policy
    /// check is the sole enforcement point for that case.
    /// </para>
    /// </remarks>
    public static readonly ImmutableHashSet<string> GatedMechanisms = ImmutableHashSet.Create(
        "CKM_MD5_RSA_PKCS",
        "CKM_SHA1_RSA_PKCS",
        "CKM_SHA1_RSA_PKCS_PSS",
        // Not cryptographically broken (FIPS 180-4-approved, just a truncated SHA-256), but gated
        // like SHA-1: no HashAlgorithmName constant in the BCL, no benefit over SHA-256 on
        // equal-cost hardware (SecureOnlyPolicy documents the refusal).
        "CKM_SHA224_RSA_PKCS",
        "CKM_SHA224_RSA_PKCS_PSS",
        "CKM_ECDSA_SHA224",
        "CKM_SHA224_HMAC",
        "CKM_MD5",
        "CKM_SHA_1",
        "CKM_DES_ECB",
        "CKM_DES_CBC",
        "CKM_DES_CBC_PAD",
        "CKM_DES3_ECB",
        "CKM_DES3_CBC",
        "CKM_DES3_CBC_PAD",
        "CKM_DES_MAC",
        "CKM_DES_MAC_GENERAL",
        "CKM_DES3_MAC",
        "CKM_DES3_MAC_GENERAL",
        "CKM_DES_KEY_GEN",
        "CKM_DES2_KEY_GEN",
        "CKM_DES3_KEY_GEN",
        "CKM_DES3_ECB_ENCRYPT_DATA",
        "CKM_DES3_CBC_ENCRYPT_DATA",
        "CKM_EXTRACT_KEY_FROM_KEY",
        "CKM_XOR_BASE_AND_DATA",
        "CKM_CONCATENATE_BASE_AND_KEY",
        "CKM_CONCATENATE_BASE_AND_DATA",
        "CKM_CONCATENATE_DATA_AND_BASE",
        "CKM_AES_ECB",
        "CKM_CAMELLIA_ECB",
        "CKM_ARIA_ECB",
        "CKM_IDEA_ECB",
        "CKM_GOST28147_ECB",
        "CKM_CHACHA20",
        "CKM_SALSA20",
        "CKM_AES_XTS",
        "CKM_AES_CBC",
        "CKM_AES_CBC_PAD",
        "CKM_AES_CTR",
        "CKM_AES_CTS",
        "CKM_AES_OFB",
        "CKM_AES_CFB1",
        "CKM_AES_CFB8",
        "CKM_AES_CFB64",
        "CKM_AES_CFB128",
        "CKM_RC4",
        "CKM_RC4_KEY_GEN",
        "CKM_RC2_ECB",
        "CKM_RC2_CBC",
        "CKM_RC2_CBC_PAD",
        "CKM_RC2_MAC",
        "CKM_RC2_MAC_GENERAL",
        "CKM_RC2_KEY_GEN",
        "CKM_SEED_ECB",
        "CKM_SEED_CBC",
        "CKM_SEED_CBC_PAD",
        "CKM_SEED_MAC",
        "CKM_SEED_MAC_GENERAL",
        "CKM_SEED_KEY_GEN",
        "CKM_SEED_CBC_ENCRYPT_DATA",
        "CKM_SEED_ECB_ENCRYPT_DATA",
        "CKM_MD2",
        "CKM_MD2_HMAC",
        "CKM_MD2_HMAC_GENERAL",
        "CKM_MD2_KEY_DERIVATION",
        "CKM_MD2_RSA_PKCS",
        "CKM_RIPEMD128",
        "CKM_RIPEMD128_HMAC",
        "CKM_RIPEMD128_HMAC_GENERAL",
        "CKM_RIPEMD128_RSA_PKCS",
        "CKM_RIPEMD160",
        "CKM_RIPEMD160_HMAC",
        "CKM_RIPEMD160_HMAC_GENERAL",
        "CKM_RIPEMD160_RSA_PKCS",
        "CKM_SHA_1_HMAC",
        "CKM_SHA_1_HMAC_GENERAL",
        "CKM_ECDSA_SHA1",
        "CKM_MD5_HMAC",
        "CKM_MD5_HMAC_GENERAL",
        "CKM_MD5_KEY_DERIVATION",
        "CKM_SHA1_KEY_DERIVATION",
        "CKM_SSL3_MD5_MAC",
        "CKM_SSL3_SHA1_MAC",
        "CKM_RSA_9796",
        "CKM_DSA",
        "CKM_DSA_SHA1",
        "CKM_DSA_SHA224",
        "CKM_DSA_SHA256",
        "CKM_DSA_SHA384",
        "CKM_DSA_SHA512",
        "CKM_CAST_ECB",
        "CKM_CAST_CBC",
        "CKM_CAST_CBC_PAD",
        "CKM_CAST_MAC",
        "CKM_CAST_MAC_GENERAL",
        "CKM_CAST_KEY_GEN",
        "CKM_CAST3_ECB",
        "CKM_CAST3_CBC",
        "CKM_CAST3_CBC_PAD",
        "CKM_CAST3_MAC",
        "CKM_CAST3_MAC_GENERAL",
        "CKM_CAST3_KEY_GEN",
        // CAST128 and CAST5 are aliases for the same CKM values; a consumer may write either
        // spelling, and the analyzer matches by field name, so both must be listed.
        "CKM_CAST128_ECB",
        "CKM_CAST5_ECB",
        "CKM_CAST128_CBC",
        "CKM_CAST5_CBC",
        "CKM_CAST128_CBC_PAD",
        "CKM_CAST5_CBC_PAD",
        "CKM_CAST128_MAC",
        "CKM_CAST5_MAC",
        "CKM_CAST128_MAC_GENERAL",
        "CKM_CAST5_MAC_GENERAL",
        "CKM_CAST128_KEY_GEN",
        "CKM_CAST5_KEY_GEN",
        "CKM_RC5_ECB",
        "CKM_RC5_CBC",
        "CKM_RC5_CBC_PAD",
        "CKM_RC5_MAC",
        "CKM_RC5_MAC_GENERAL",
        "CKM_RC5_KEY_GEN",
        "CKM_BLOWFISH_CBC",
        "CKM_BLOWFISH_CBC_PAD",
        "CKM_BLOWFISH_KEY_GEN",
        "CKM_SKIPJACK_KEY_GEN",
        "CKM_SKIPJACK_ECB64",
        "CKM_SKIPJACK_CBC64",
        "CKM_SKIPJACK_OFB64",
        "CKM_SKIPJACK_CFB64",
        "CKM_SKIPJACK_CFB32",
        "CKM_SKIPJACK_CFB16",
        "CKM_SKIPJACK_CFB8",
        "CKM_SKIPJACK_WRAP",
        "CKM_SKIPJACK_PRIVATE_WRAP",
        "CKM_SKIPJACK_RELAYX",
        // CBC-MAC over AES / TDEA CMAC.
        "CKM_AES_MAC",
        "CKM_AES_MAC_GENERAL",
        "CKM_DES3_CMAC",
        "CKM_DES3_CMAC_GENERAL",
        "CKM_AES_KEY_WRAP_PKCS7",
        // Truncated hashes with no benefit over SHA-256.
        "CKM_SHA224",
        "CKM_SHA3_224",
        "CKM_SHA512_224",
        "CKM_SHA512_T",
        "CKM_DSA_KEY_PAIR_GEN",
        "CKM_RSA_X9_31_KEY_PAIR_GEN",
        // Hash-of-key derivation. The SHA-3 and SHAKE ones have two spellings sharing a value.
        "CKM_SHA224_KEY_DERIVATION",
        "CKM_SHA256_KEY_DERIVATION",
        "CKM_SHA384_KEY_DERIVATION",
        "CKM_SHA512_KEY_DERIVATION",
        "CKM_SHA512_224_KEY_DERIVATION",
        "CKM_SHA512_256_KEY_DERIVATION",
        "CKM_SHA512_T_KEY_DERIVATION",
        "CKM_SHA3_224_KEY_DERIVE",
        "CKM_SHA3_224_KEY_DERIVATION",
        "CKM_SHA3_256_KEY_DERIVE",
        "CKM_SHA3_256_KEY_DERIVATION",
        "CKM_SHA3_384_KEY_DERIVE",
        "CKM_SHA3_384_KEY_DERIVATION",
        "CKM_SHA3_512_KEY_DERIVE",
        "CKM_SHA3_512_KEY_DERIVATION",
        "CKM_SHAKE_128_KEY_DERIVE",
        "CKM_SHAKE_128_KEY_DERIVATION",
        "CKM_SHAKE_256_KEY_DERIVE",
        "CKM_SHAKE_256_KEY_DERIVATION",
        // IKE PRFs: protocol-specific, opt in explicitly after review.
        "CKM_IKE_PRF_DERIVE",
        "CKM_IKE1_PRF_DERIVE",
        "CKM_IKE1_EXTENDED_DERIVE",
        "CKM_IKE2_PRF_PLUS_DERIVE"
    );

    /// <summary>Unauthenticated / malleable AES modes; the authenticated modes are GCM and CCM.</summary>
    public static readonly ImmutableHashSet<string> WeakCipherModes = ImmutableHashSet.Create(
        "ECB", "CBC", "CFB", "OFB", "CTS"
    );
}
