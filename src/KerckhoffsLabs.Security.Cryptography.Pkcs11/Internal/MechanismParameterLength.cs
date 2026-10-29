using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The lengths PKCS#11 allows a standard mechanism's parameter, for the raw-block constructor of
/// <see cref="Mechanism"/> to check before any call is made.
/// </summary>
/// <remarks>
/// <para>
/// A token is told the parameter's length, but one that reads the parameter's full layout regardless
/// would read past a shorter block into whatever memory follows it. Every standard mechanism whose
/// parameter has a fixed layout is therefore held to that layout's length:
/// </para>
/// <list type="bullet">
/// <item>a bare block (an IV of the cipher's block size, a <c>CK_VERSION</c>);</item>
/// <item>a struct, at its size on this platform: <see cref="Pkcs11Marshal.SizeOf{T}()"/>, the size this
/// library marshals it at (packed on Windows, natural elsewhere). For a struct holding pointers, the
/// pointers in a raw block stay the caller's to get right; only the length is checked.</item>
/// </list>
/// <para>
/// A mechanism whose parameter is optional also takes an empty block. A mechanism whose parameter type
/// depends on the function it is used with (AES-GCM through <c>C_Encrypt</c>, the message API or
/// <c>C_WrapKey</c>) takes any of those structs' sizes. Mechanisms with a variable-length parameter (a DH
/// peer value, a GOST OID), with none, and vendor mechanisms have no rule: their block stays the caller's
/// to lay out.
/// </para>
/// </remarks>
internal static class MechanismParameterLength
{
    /// <summary>What a mechanism's parameter must be: a description and the lengths it may have.</summary>
    internal readonly record struct Rule(string What, int[] Lengths);

    /// <summary>The rule for <paramref name="type"/>'s parameter, or <see langword="null"/> when it has none.</summary>
    internal static Rule? For(CKM type) => type switch
    {
        // An IV of the cipher's 16-byte block.
        CKM.CKM_AES_CBC or CKM.CKM_AES_CBC_PAD or CKM.CKM_AES_OFB or CKM.CKM_AES_CFB1 or CKM.CKM_AES_CFB8
            or CKM.CKM_AES_CFB64 or CKM.CKM_AES_CFB128 or CKM.CKM_AES_CTS
            or CKM.CKM_CAMELLIA_CBC or CKM.CKM_CAMELLIA_CBC_PAD or CKM.CKM_ARIA_CBC or CKM.CKM_ARIA_CBC_PAD
            or CKM.CKM_SEED_CBC or CKM.CKM_SEED_CBC_PAD or CKM.CKM_TWOFISH_CBC or CKM.CKM_TWOFISH_CBC_PAD
            => Iv(16),

        // An IV of the cipher's 8-byte block.
        CKM.CKM_DES_CBC or CKM.CKM_DES_CBC_PAD or CKM.CKM_DES3_CBC or CKM.CKM_DES3_CBC_PAD
            or CKM.CKM_DES_OFB8 or CKM.CKM_DES_OFB64 or CKM.CKM_DES_CFB8 or CKM.CKM_DES_CFB64
            or CKM.CKM_BLOWFISH_CBC or CKM.CKM_BLOWFISH_CBC_PAD or CKM.CKM_CDMF_CBC or CKM.CKM_CDMF_CBC_PAD
            or CKM.CKM_CAST_CBC or CKM.CKM_CAST_CBC_PAD or CKM.CKM_CAST3_CBC or CKM.CKM_CAST3_CBC_PAD
            or CKM.CKM_CAST5_CBC or CKM.CKM_CAST5_CBC_PAD or CKM.CKM_CAST128_CBC or CKM.CKM_CAST128_CBC_PAD
            or CKM.CKM_IDEA_CBC or CKM.CKM_IDEA_CBC_PAD
            => Iv(8),

        // The 24-byte IV of the Fortezza-era ciphers.
        CKM.CKM_SKIPJACK_ECB64 or CKM.CKM_SKIPJACK_CBC64 or CKM.CKM_SKIPJACK_OFB64 or CKM.CKM_SKIPJACK_CFB64
            or CKM.CKM_SKIPJACK_CFB32 or CKM.CKM_SKIPJACK_CFB16 or CKM.CKM_SKIPJACK_CFB8
            or CKM.CKM_BATON_ECB128 or CKM.CKM_BATON_ECB96 or CKM.CKM_BATON_CBC128 or CKM.CKM_BATON_COUNTER
            or CKM.CKM_BATON_SHUFFLE or CKM.CKM_JUNIPER_ECB128 or CKM.CKM_JUNIPER_CBC128
            or CKM.CKM_JUNIPER_COUNTER or CKM.CKM_JUNIPER_SHUFFLE
            => Iv(24),

        CKM.CKM_AES_XTS => new("a 16-byte data unit sequence number", [16]),

        // Optional IVs: none, or exactly one of the given length.
        CKM.CKM_AES_KEY_WRAP or CKM.CKM_AES_KEY_WRAP_PKCS7 or CKM.CKM_AES_KEY_WRAP_PAD => OptionalIv(8),
        CKM.CKM_AES_KEY_WRAP_KWP => OptionalIv(4),
        CKM.CKM_GOST28147 or CKM.CKM_GOST28147_MAC or CKM.CKM_GOST28147_KEY_WRAP => OptionalIv(8),

        CKM.CKM_SSL3_PRE_MASTER_KEY_GEN or CKM.CKM_TLS_PRE_MASTER_KEY_GEN => new("a 2-byte CK_VERSION", [2]),
        CKM.CKM_WTLS_PRE_MASTER_KEY_GEN => new("a 1-byte CK_BYTE", [1]),

        // A single CK_ULONG.
        CKM.CKM_MD2_HMAC_GENERAL or CKM.CKM_MD5_HMAC_GENERAL or CKM.CKM_SHA_1_HMAC_GENERAL
            or CKM.CKM_RIPEMD128_HMAC_GENERAL or CKM.CKM_RIPEMD160_HMAC_GENERAL
            or CKM.CKM_SHA224_HMAC_GENERAL or CKM.CKM_SHA256_HMAC_GENERAL or CKM.CKM_SHA384_HMAC_GENERAL
            or CKM.CKM_SHA512_HMAC_GENERAL or CKM.CKM_SHA512_224_HMAC_GENERAL or CKM.CKM_SHA512_256_HMAC_GENERAL
            or CKM.CKM_SHA512_T_HMAC_GENERAL or CKM.CKM_SHA3_224_HMAC_GENERAL or CKM.CKM_SHA3_256_HMAC_GENERAL
            or CKM.CKM_SHA3_384_HMAC_GENERAL or CKM.CKM_SHA3_512_HMAC_GENERAL
            or CKM.CKM_BLAKE2B_160_HMAC_GENERAL or CKM.CKM_BLAKE2B_256_HMAC_GENERAL
            or CKM.CKM_BLAKE2B_384_HMAC_GENERAL or CKM.CKM_BLAKE2B_512_HMAC_GENERAL
            or CKM.CKM_DES_MAC_GENERAL or CKM.CKM_DES3_MAC_GENERAL or CKM.CKM_CDMF_MAC_GENERAL
            or CKM.CKM_CAST_MAC_GENERAL or CKM.CKM_CAST3_MAC_GENERAL or CKM.CKM_CAST5_MAC_GENERAL
            or CKM.CKM_CAST128_MAC_GENERAL or CKM.CKM_IDEA_MAC_GENERAL or CKM.CKM_CAMELLIA_MAC_GENERAL
            or CKM.CKM_ARIA_MAC_GENERAL or CKM.CKM_SEED_MAC_GENERAL or CKM.CKM_AES_MAC_GENERAL
            or CKM.CKM_AES_CMAC_GENERAL or CKM.CKM_DES3_CMAC_GENERAL
            or CKM.CKM_SHA512_T or CKM.CKM_SHA512_T_HMAC or CKM.CKM_SSL3_MD5_MAC or CKM.CKM_SSL3_SHA1_MAC
            => Struct<CK_MAC_GENERAL_PARAMS>(nameof(CK_MAC_GENERAL_PARAMS)),
        CKM.CKM_RC2_ECB or CKM.CKM_RC2_MAC => Struct<CK_RC2_PARAMS>(nameof(CK_RC2_PARAMS)),
        CKM.CKM_EXTRACT_KEY_FROM_KEY => Struct<CK_EXTRACT_PARAMS>(nameof(CK_EXTRACT_PARAMS)),
        CKM.CKM_XEDDSA => Struct<CK_XEDDSA_PARAMS>(nameof(CK_XEDDSA_PARAMS)),
        CKM.CKM_CONCATENATE_BASE_AND_KEY => Struct<NativeCULong>("CK_OBJECT_HANDLE"),

        // Structs of CK_ULONGs and bytes.
        CKM.CKM_RC2_CBC or CKM.CKM_RC2_CBC_PAD => Struct<CK_RC2_CBC_PARAMS>(nameof(CK_RC2_CBC_PARAMS)),
        CKM.CKM_RC2_MAC_GENERAL => Struct<CK_RC2_MAC_GENERAL_PARAMS>(nameof(CK_RC2_MAC_GENERAL_PARAMS)),
        CKM.CKM_RC5_ECB or CKM.CKM_RC5_MAC => Struct<CK_RC5_PARAMS>(nameof(CK_RC5_PARAMS)),
        CKM.CKM_RC5_MAC_GENERAL => Struct<CK_RC5_MAC_GENERAL_PARAMS>(nameof(CK_RC5_MAC_GENERAL_PARAMS)),
        CKM.CKM_AES_CTR => Struct<CK_AES_CTR_PARAMS>(nameof(CK_AES_CTR_PARAMS)),
        CKM.CKM_CAMELLIA_CTR => Struct<CK_CAMELLIA_CTR_PARAMS>(nameof(CK_CAMELLIA_CTR_PARAMS)),
        CKM.CKM_RSA_PKCS_PSS or CKM.CKM_SHA1_RSA_PKCS_PSS or CKM.CKM_SHA224_RSA_PKCS_PSS
            or CKM.CKM_SHA256_RSA_PKCS_PSS or CKM.CKM_SHA384_RSA_PKCS_PSS or CKM.CKM_SHA512_RSA_PKCS_PSS
            or CKM.CKM_SHA3_224_RSA_PKCS_PSS or CKM.CKM_SHA3_256_RSA_PKCS_PSS or CKM.CKM_SHA3_384_RSA_PKCS_PSS
            or CKM.CKM_SHA3_512_RSA_PKCS_PSS
            => Struct<CK_RSA_PKCS_PSS_PARAMS>(nameof(CK_RSA_PKCS_PSS_PARAMS)),
        CKM.CKM_TLS_MAC or CKM.CKM_TLS12_MAC => Struct<CK_TLS_MAC_PARAMS>(nameof(CK_TLS_MAC_PARAMS)),

        // Structs holding pointers.
        CKM.CKM_AES_GCM => Structs(
            (nameof(CK_GCM_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_PARAMS>()),
            (nameof(CK_GCM_MESSAGE_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_MESSAGE_PARAMS>()),
            (nameof(CK_GCM_WRAP_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_WRAP_PARAMS>())),
        CKM.CKM_AES_CCM => Structs(
            (nameof(CK_CCM_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_PARAMS>()),
            (nameof(CK_CCM_MESSAGE_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_MESSAGE_PARAMS>()),
            (nameof(CK_CCM_WRAP_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_WRAP_PARAMS>())),
        CKM.CKM_CHACHA20_POLY1305 or CKM.CKM_SALSA20_POLY1305 => Structs(
            (nameof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_PARAMS>()),
            (nameof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>())),
        CKM.CKM_CHACHA20 => Struct<CK_CHACHA20_PARAMS>(nameof(CK_CHACHA20_PARAMS)),
        CKM.CKM_SALSA20 => Struct<CK_SALSA20_PARAMS>(nameof(CK_SALSA20_PARAMS)),
        CKM.CKM_RSA_PKCS_OAEP => Struct<CK_RSA_PKCS_OAEP_PARAMS>(nameof(CK_RSA_PKCS_OAEP_PARAMS)),
        CKM.CKM_RSA_AES_KEY_WRAP => Struct<CK_RSA_AES_KEY_WRAP_PARAMS>(nameof(CK_RSA_AES_KEY_WRAP_PARAMS)),
        CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE => Struct<CK_ECDH1_DERIVE_PARAMS>(nameof(CK_ECDH1_DERIVE_PARAMS)),
        CKM.CKM_ECMQV_DERIVE => Struct<CK_ECMQV_DERIVE_PARAMS>(nameof(CK_ECMQV_DERIVE_PARAMS)),
        CKM.CKM_ECDH_AES_KEY_WRAP or CKM.CKM_ECDH_COF_AES_KEY_WRAP or CKM.CKM_ECDH_X_AES_KEY_WRAP
            => Struct<CK_ECDH_AES_KEY_WRAP_PARAMS>(nameof(CK_ECDH_AES_KEY_WRAP_PARAMS)),
        CKM.CKM_X9_42_DH_DERIVE => Struct<CK_X9_42_DH1_DERIVE_PARAMS>(nameof(CK_X9_42_DH1_DERIVE_PARAMS)),
        CKM.CKM_X9_42_DH_HYBRID_DERIVE => Struct<CK_X9_42_DH2_DERIVE_PARAMS>(nameof(CK_X9_42_DH2_DERIVE_PARAMS)),
        CKM.CKM_X9_42_MQV_DERIVE => Struct<CK_X9_42_MQV_DERIVE_PARAMS>(nameof(CK_X9_42_MQV_DERIVE_PARAMS)),
        CKM.CKM_KEA_DERIVE or CKM.CKM_KEA_KEY_DERIVE => Struct<CK_KEA_DERIVE_PARAMS>(nameof(CK_KEA_DERIVE_PARAMS)),
        CKM.CKM_DSA_PROBABILISTIC_PARAMETER_GEN or CKM.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN or CKM.CKM_DSA_FIPS_G_GEN
            => Struct<CK_DSA_PARAMETER_GEN_PARAM>(nameof(CK_DSA_PARAMETER_GEN_PARAM)),
        CKM.CKM_RC5_CBC or CKM.CKM_RC5_CBC_PAD => Struct<CK_RC5_CBC_PARAMS>(nameof(CK_RC5_CBC_PARAMS)),
        CKM.CKM_DES_CBC_ENCRYPT_DATA or CKM.CKM_DES3_CBC_ENCRYPT_DATA
            => Struct<CK_DES_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_DES_CBC_ENCRYPT_DATA_PARAMS)),
        CKM.CKM_AES_CBC_ENCRYPT_DATA => Struct<CK_AES_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)),
        CKM.CKM_ARIA_CBC_ENCRYPT_DATA => Struct<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)),
        CKM.CKM_CAMELLIA_CBC_ENCRYPT_DATA => Struct<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)),
        CKM.CKM_SEED_CBC_ENCRYPT_DATA => Struct<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS)),
        CKM.CKM_DES_ECB_ENCRYPT_DATA or CKM.CKM_DES3_ECB_ENCRYPT_DATA or CKM.CKM_AES_ECB_ENCRYPT_DATA
            or CKM.CKM_ARIA_ECB_ENCRYPT_DATA or CKM.CKM_CAMELLIA_ECB_ENCRYPT_DATA or CKM.CKM_SEED_ECB_ENCRYPT_DATA
            or CKM.CKM_CONCATENATE_BASE_AND_DATA or CKM.CKM_CONCATENATE_DATA_AND_BASE or CKM.CKM_XOR_BASE_AND_DATA
            => Struct<CK_KEY_DERIVATION_STRING_DATA>(nameof(CK_KEY_DERIVATION_STRING_DATA)),
        CKM.CKM_SKIPJACK_PRIVATE_WRAP => Struct<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>(nameof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)),
        CKM.CKM_SKIPJACK_RELAYX => Struct<CK_SKIPJACK_RELAYX_PARAMS>(nameof(CK_SKIPJACK_RELAYX_PARAMS)),
        CKM.CKM_PBE_MD2_DES_CBC or CKM.CKM_PBE_MD5_DES_CBC or CKM.CKM_PBE_MD5_CAST_CBC or CKM.CKM_PBE_MD5_CAST3_CBC
            or CKM.CKM_PBE_MD5_CAST5_CBC or CKM.CKM_PBE_MD5_CAST128_CBC or CKM.CKM_PBE_SHA1_CAST5_CBC
            or CKM.CKM_PBE_SHA1_CAST128_CBC or CKM.CKM_PBE_SHA1_RC4_128 or CKM.CKM_PBE_SHA1_RC4_40
            or CKM.CKM_PBE_SHA1_DES3_EDE_CBC or CKM.CKM_PBE_SHA1_DES2_EDE_CBC or CKM.CKM_PBE_SHA1_RC2_128_CBC
            or CKM.CKM_PBE_SHA1_RC2_40_CBC or CKM.CKM_PBA_SHA1_WITH_SHA1_HMAC
            => Struct<CK_PBE_PARAMS>(nameof(CK_PBE_PARAMS)),
        CKM.CKM_PKCS5_PBKD2 => Structs(
            (nameof(CK_PKCS5_PBKD2_PARAMS2), Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS2>()),
            (nameof(CK_PKCS5_PBKD2_PARAMS), Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS>())),
        CKM.CKM_KEY_WRAP_SET_OAEP => Struct<CK_KEY_WRAP_SET_OAEP_PARAMS>(nameof(CK_KEY_WRAP_SET_OAEP_PARAMS)),
        CKM.CKM_SSL3_MASTER_KEY_DERIVE or CKM.CKM_SSL3_MASTER_KEY_DERIVE_DH
            or CKM.CKM_TLS_MASTER_KEY_DERIVE or CKM.CKM_TLS_MASTER_KEY_DERIVE_DH
            => Struct<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)),
        CKM.CKM_SSL3_KEY_AND_MAC_DERIVE or CKM.CKM_TLS_KEY_AND_MAC_DERIVE
            => Struct<CK_SSL3_KEY_MAT_PARAMS>(nameof(CK_SSL3_KEY_MAT_PARAMS)),
        CKM.CKM_TLS_PRF => Struct<CK_TLS_PRF_PARAMS>(nameof(CK_TLS_PRF_PARAMS)),
        CKM.CKM_TLS12_MASTER_KEY_DERIVE or CKM.CKM_TLS12_MASTER_KEY_DERIVE_DH
            => Struct<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS)),
        CKM.CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE or CKM.CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
            => Struct<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS)),
        // PKCS#11 v3.2 names CK_TLS12_KEY_MAT_PARAMS for these in the header and in one place in the text,
        // and CK_SSL3_KEY_MAT_PARAMS in another, so either is taken.
        CKM.CKM_TLS12_KEY_AND_MAC_DERIVE or CKM.CKM_TLS12_KEY_SAFE_DERIVE => Structs(
            (nameof(CK_TLS12_KEY_MAT_PARAMS), Pkcs11Marshal.SizeOf<CK_TLS12_KEY_MAT_PARAMS>()),
            (nameof(CK_SSL3_KEY_MAT_PARAMS), Pkcs11Marshal.SizeOf<CK_SSL3_KEY_MAT_PARAMS>())),
        CKM.CKM_TLS_KDF or CKM.CKM_TLS12_KDF => Struct<CK_TLS_KDF_PARAMS>(nameof(CK_TLS_KDF_PARAMS)),
        CKM.CKM_WTLS_MASTER_KEY_DERIVE or CKM.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
            => Struct<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)),
        CKM.CKM_WTLS_PRF => Struct<CK_WTLS_PRF_PARAMS>(nameof(CK_WTLS_PRF_PARAMS)),
        CKM.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE or CKM.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
            => Struct<CK_WTLS_KEY_MAT_PARAMS>(nameof(CK_WTLS_KEY_MAT_PARAMS)),
        CKM.CKM_CMS_SIG => Struct<CK_CMS_SIG_PARAMS>(nameof(CK_CMS_SIG_PARAMS)),
        CKM.CKM_KIP_DERIVE or CKM.CKM_KIP_WRAP or CKM.CKM_KIP_MAC => Struct<CK_KIP_PARAMS>(nameof(CK_KIP_PARAMS)),
        CKM.CKM_SECURID or CKM.CKM_HOTP or CKM.CKM_ACTI => OptionalStruct<CK_OTP_PARAMS>(nameof(CK_OTP_PARAMS)),
        CKM.CKM_GOSTR3410_KEY_WRAP => Struct<CK_GOSTR3410_KEY_WRAP_PARAMS>(nameof(CK_GOSTR3410_KEY_WRAP_PARAMS)),
        CKM.CKM_GOSTR3410_DERIVE => Struct<CK_GOSTR3410_DERIVE_PARAMS>(nameof(CK_GOSTR3410_DERIVE_PARAMS)),
        CKM.CKM_SP800_108_COUNTER_KDF or CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF
            => Struct<CK_SP800_108_KDF_PARAMS>(nameof(CK_SP800_108_KDF_PARAMS)),
        CKM.CKM_SP800_108_FEEDBACK_KDF => Struct<CK_SP800_108_FEEDBACK_KDF_PARAMS>(nameof(CK_SP800_108_FEEDBACK_KDF_PARAMS)),
        CKM.CKM_X3DH_INITIALIZE => Struct<CK_X3DH_INITIATE_PARAMS>(nameof(CK_X3DH_INITIATE_PARAMS)),
        CKM.CKM_X3DH_RESPOND => Struct<CK_X3DH_RESPOND_PARAMS>(nameof(CK_X3DH_RESPOND_PARAMS)),
        CKM.CKM_X2RATCHET_INITIALIZE => Struct<CK_X2RATCHET_INITIALIZE_PARAMS>(nameof(CK_X2RATCHET_INITIALIZE_PARAMS)),
        CKM.CKM_X2RATCHET_RESPOND => Struct<CK_X2RATCHET_RESPOND_PARAMS>(nameof(CK_X2RATCHET_RESPOND_PARAMS)),
        CKM.CKM_HKDF_DERIVE or CKM.CKM_HKDF_DATA => Struct<CK_HKDF_PARAMS>(nameof(CK_HKDF_PARAMS)),
        CKM.CKM_IKE2_PRF_PLUS_DERIVE => Struct<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>(nameof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS)),
        CKM.CKM_IKE_PRF_DERIVE => Struct<CK_IKE_PRF_DERIVE_PARAMS>(nameof(CK_IKE_PRF_DERIVE_PARAMS)),
        CKM.CKM_IKE1_PRF_DERIVE => Struct<CK_IKE1_PRF_DERIVE_PARAMS>(nameof(CK_IKE1_PRF_DERIVE_PARAMS)),
        CKM.CKM_IKE1_EXTENDED_DERIVE => Struct<CK_IKE1_EXTENDED_DERIVE_PARAMS>(nameof(CK_IKE1_EXTENDED_DERIVE_PARAMS)),
        CKM.CKM_EDDSA => OptionalStruct<CK_EDDSA_PARAMS>(nameof(CK_EDDSA_PARAMS)),
        CKM.CKM_ML_DSA or CKM.CKM_SLH_DSA
            or CKM.CKM_HASH_ML_DSA_SHA224 or CKM.CKM_HASH_ML_DSA_SHA256 or CKM.CKM_HASH_ML_DSA_SHA384
            or CKM.CKM_HASH_ML_DSA_SHA512 or CKM.CKM_HASH_ML_DSA_SHA3_224 or CKM.CKM_HASH_ML_DSA_SHA3_256
            or CKM.CKM_HASH_ML_DSA_SHA3_384 or CKM.CKM_HASH_ML_DSA_SHA3_512 or CKM.CKM_HASH_ML_DSA_SHAKE128
            or CKM.CKM_HASH_ML_DSA_SHAKE256
            or CKM.CKM_HASH_SLH_DSA_SHA224 or CKM.CKM_HASH_SLH_DSA_SHA256 or CKM.CKM_HASH_SLH_DSA_SHA384
            or CKM.CKM_HASH_SLH_DSA_SHA512 or CKM.CKM_HASH_SLH_DSA_SHA3_224 or CKM.CKM_HASH_SLH_DSA_SHA3_256
            or CKM.CKM_HASH_SLH_DSA_SHA3_384 or CKM.CKM_HASH_SLH_DSA_SHA3_512 or CKM.CKM_HASH_SLH_DSA_SHAKE128
            or CKM.CKM_HASH_SLH_DSA_SHAKE256
            => OptionalStruct<CK_SIGN_ADDITIONAL_CONTEXT>(nameof(CK_SIGN_ADDITIONAL_CONTEXT)),
        CKM.CKM_HASH_ML_DSA or CKM.CKM_HASH_SLH_DSA
            => Struct<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(nameof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)),
        _ => null,
    };

    /// <summary>The message for a parameter of <paramref name="length"/> bytes that breaks <paramref name="rule"/>.</summary>
    internal static string Describe(CKM type, Rule rule, int length)
        => $"{type} takes {rule.What} as its parameter, not {length} bytes.";

    private static Rule Iv(int length) => new($"a {length}-byte IV", [length]);

    private static Rule OptionalIv(int length) => new($"no parameter or a {length}-byte IV", [0, length]);

    private static Rule Struct<T>(string name) where T : unmanaged
    {
        int size = Pkcs11Marshal.SizeOf<T>();
        return new($"a {name} ({size} bytes on this platform)", [size]);
    }

    private static Rule OptionalStruct<T>(string name) where T : unmanaged
    {
        int size = Pkcs11Marshal.SizeOf<T>();
        return new($"no parameter or a {name} ({size} bytes on this platform)", [0, size]);
    }

    private static Rule Structs(params (string Name, int Size)[] structs)
        => new(
            $"a {string.Join(" or a ", structs.Select(s => $"{s.Name} ({s.Size} bytes on this platform)"))}",
            [.. structs.Select(s => s.Size).Distinct()]);
}
