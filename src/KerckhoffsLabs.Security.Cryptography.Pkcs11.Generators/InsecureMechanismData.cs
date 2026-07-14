using System.Collections.Immutable;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

/// <summary>
/// The mechanism/mode names <see cref="InsecureMechanismAnalyzer"/> reports on (KLPKCS11009).
/// </summary>
/// <remarks>
/// Deliberately free of any Roslyn type: the library's test project reads these sets to pin them
/// against what <c>Pkcs11Session.GuardMechanism</c> actually rejects at run time, and touching a type
/// that derived from <c>DiagnosticAnalyzer</c> would drag the compiler assemblies into the test host.
/// The analyzer cannot simply reference the library's <c>CKM</c> enum — it targets netstandard2.0 and
/// referencing the library would be a cycle — so this list is a transcription, and the parity tests
/// exist to make sure it never drifts from the guard.
/// </remarks>
public static class InsecureMechanismData
{
    /// <summary>
    /// Mechanisms rejected by the runtime gate, minus the RSA-encryption pair covered by KLPKCS11008.
    /// </summary>
    public static readonly ImmutableHashSet<string> GatedMechanisms = ImmutableHashSet.Create(
        "CKM_MD5_RSA_PKCS",
        "CKM_SHA1_RSA_PKCS",
        "CKM_SHA1_RSA_PKCS_PSS",
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
        "CKM_AES_ECB",
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
        "CKM_SKIPJACK_RELAYX"
    );

    /// <summary>Unauthenticated / malleable AES modes; the authenticated modes are GCM and CCM.</summary>
    public static readonly ImmutableHashSet<string> WeakCipherModes = ImmutableHashSet.Create(
        "ECB", "CBC", "CFB", "OFB", "CTS"
    );
}
