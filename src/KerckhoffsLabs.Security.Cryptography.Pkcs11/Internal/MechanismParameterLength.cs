using System.Collections;
using System.Collections.Frozen;
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

    // A table, not a switch: one rule per group of mechanisms. A mechanism named in two groups fails the
    // type's initialization, where a switch would have flagged the second arm as subsumed.
    private static readonly FrozenDictionary<CKM, Rule> Rules = new RuleTable
    {
        // An IV of the cipher's 16-byte block.
        { Iv(16),
            CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_OFB, CKM.CKM_AES_CFB1, CKM.CKM_AES_CFB8,
            CKM.CKM_AES_CFB64, CKM.CKM_AES_CFB128, CKM.CKM_AES_CTS, CKM.CKM_CAMELLIA_CBC, CKM.CKM_CAMELLIA_CBC_PAD,
            CKM.CKM_ARIA_CBC, CKM.CKM_ARIA_CBC_PAD, CKM.CKM_SEED_CBC, CKM.CKM_SEED_CBC_PAD, CKM.CKM_TWOFISH_CBC,
            CKM.CKM_TWOFISH_CBC_PAD },

        // An IV of the cipher's 8-byte block.
        { Iv(8),
            CKM.CKM_DES_CBC, CKM.CKM_DES_CBC_PAD, CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD, CKM.CKM_DES_OFB8,
            CKM.CKM_DES_OFB64, CKM.CKM_DES_CFB8, CKM.CKM_DES_CFB64, CKM.CKM_BLOWFISH_CBC, CKM.CKM_BLOWFISH_CBC_PAD,
            CKM.CKM_CDMF_CBC, CKM.CKM_CDMF_CBC_PAD, CKM.CKM_CAST_CBC, CKM.CKM_CAST_CBC_PAD, CKM.CKM_CAST3_CBC,
            CKM.CKM_CAST3_CBC_PAD, CKM.CKM_CAST5_CBC, CKM.CKM_CAST5_CBC_PAD, CKM.CKM_CAST128_CBC,
            CKM.CKM_CAST128_CBC_PAD, CKM.CKM_IDEA_CBC, CKM.CKM_IDEA_CBC_PAD },

        // The 24-byte IV of the Fortezza-era ciphers.
        { Iv(24),
            CKM.CKM_SKIPJACK_ECB64, CKM.CKM_SKIPJACK_CBC64, CKM.CKM_SKIPJACK_OFB64, CKM.CKM_SKIPJACK_CFB64,
            CKM.CKM_SKIPJACK_CFB32, CKM.CKM_SKIPJACK_CFB16, CKM.CKM_SKIPJACK_CFB8, CKM.CKM_BATON_ECB128,
            CKM.CKM_BATON_ECB96, CKM.CKM_BATON_CBC128, CKM.CKM_BATON_COUNTER, CKM.CKM_BATON_SHUFFLE,
            CKM.CKM_JUNIPER_ECB128, CKM.CKM_JUNIPER_CBC128, CKM.CKM_JUNIPER_COUNTER, CKM.CKM_JUNIPER_SHUFFLE },

        { new("a 16-byte data unit sequence number", [16]), CKM.CKM_AES_XTS },

        // Optional IVs: none, or exactly one of the given length.
        { OptionalIv(8), CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_PKCS7, CKM.CKM_AES_KEY_WRAP_PAD },
        { OptionalIv(4), CKM.CKM_AES_KEY_WRAP_KWP },
        { OptionalIv(8), CKM.CKM_GOST28147, CKM.CKM_GOST28147_MAC, CKM.CKM_GOST28147_KEY_WRAP },

        { new("a 2-byte CK_VERSION", [2]), CKM.CKM_SSL3_PRE_MASTER_KEY_GEN, CKM.CKM_TLS_PRE_MASTER_KEY_GEN },
        { new("a 1-byte CK_BYTE", [1]), CKM.CKM_WTLS_PRE_MASTER_KEY_GEN },

        // A single CK_ULONG.
        { Struct<CK_MAC_GENERAL_PARAMS>(nameof(CK_MAC_GENERAL_PARAMS)),
            CKM.CKM_MD2_HMAC_GENERAL, CKM.CKM_MD5_HMAC_GENERAL, CKM.CKM_SHA_1_HMAC_GENERAL,
            CKM.CKM_RIPEMD128_HMAC_GENERAL, CKM.CKM_RIPEMD160_HMAC_GENERAL, CKM.CKM_SHA224_HMAC_GENERAL,
            CKM.CKM_SHA256_HMAC_GENERAL, CKM.CKM_SHA384_HMAC_GENERAL, CKM.CKM_SHA512_HMAC_GENERAL,
            CKM.CKM_SHA512_224_HMAC_GENERAL, CKM.CKM_SHA512_256_HMAC_GENERAL, CKM.CKM_SHA512_T_HMAC_GENERAL,
            CKM.CKM_SHA3_224_HMAC_GENERAL, CKM.CKM_SHA3_256_HMAC_GENERAL, CKM.CKM_SHA3_384_HMAC_GENERAL,
            CKM.CKM_SHA3_512_HMAC_GENERAL, CKM.CKM_BLAKE2B_160_HMAC_GENERAL, CKM.CKM_BLAKE2B_256_HMAC_GENERAL,
            CKM.CKM_BLAKE2B_384_HMAC_GENERAL, CKM.CKM_BLAKE2B_512_HMAC_GENERAL, CKM.CKM_DES_MAC_GENERAL,
            CKM.CKM_DES3_MAC_GENERAL, CKM.CKM_CDMF_MAC_GENERAL, CKM.CKM_CAST_MAC_GENERAL, CKM.CKM_CAST3_MAC_GENERAL,
            CKM.CKM_CAST5_MAC_GENERAL, CKM.CKM_CAST128_MAC_GENERAL, CKM.CKM_IDEA_MAC_GENERAL,
            CKM.CKM_CAMELLIA_MAC_GENERAL, CKM.CKM_ARIA_MAC_GENERAL, CKM.CKM_SEED_MAC_GENERAL,
            CKM.CKM_AES_MAC_GENERAL, CKM.CKM_AES_CMAC_GENERAL, CKM.CKM_DES3_CMAC_GENERAL, CKM.CKM_SHA512_T,
            CKM.CKM_SHA512_T_HMAC, CKM.CKM_SSL3_MD5_MAC, CKM.CKM_SSL3_SHA1_MAC },
        { Struct<CK_RC2_PARAMS>(nameof(CK_RC2_PARAMS)), CKM.CKM_RC2_ECB, CKM.CKM_RC2_MAC },
        { Struct<CK_EXTRACT_PARAMS>(nameof(CK_EXTRACT_PARAMS)), CKM.CKM_EXTRACT_KEY_FROM_KEY },
        { Struct<CK_XEDDSA_PARAMS>(nameof(CK_XEDDSA_PARAMS)), CKM.CKM_XEDDSA },
        { Struct<NativeCULong>("CK_OBJECT_HANDLE"), CKM.CKM_CONCATENATE_BASE_AND_KEY },

        // Structs of CK_ULONGs and bytes.
        { Struct<CK_RC2_CBC_PARAMS>(nameof(CK_RC2_CBC_PARAMS)), CKM.CKM_RC2_CBC, CKM.CKM_RC2_CBC_PAD },
        { Struct<CK_RC2_MAC_GENERAL_PARAMS>(nameof(CK_RC2_MAC_GENERAL_PARAMS)), CKM.CKM_RC2_MAC_GENERAL },
        { Struct<CK_RC5_PARAMS>(nameof(CK_RC5_PARAMS)), CKM.CKM_RC5_ECB, CKM.CKM_RC5_MAC },
        { Struct<CK_RC5_MAC_GENERAL_PARAMS>(nameof(CK_RC5_MAC_GENERAL_PARAMS)), CKM.CKM_RC5_MAC_GENERAL },
        { Struct<CK_AES_CTR_PARAMS>(nameof(CK_AES_CTR_PARAMS)), CKM.CKM_AES_CTR },
        { Struct<CK_CAMELLIA_CTR_PARAMS>(nameof(CK_CAMELLIA_CTR_PARAMS)), CKM.CKM_CAMELLIA_CTR },
        { Struct<CK_RSA_PKCS_PSS_PARAMS>(nameof(CK_RSA_PKCS_PSS_PARAMS)),
            CKM.CKM_RSA_PKCS_PSS, CKM.CKM_SHA1_RSA_PKCS_PSS, CKM.CKM_SHA224_RSA_PKCS_PSS,
            CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_SHA3_224_RSA_PKCS_PSS, CKM.CKM_SHA3_256_RSA_PKCS_PSS, CKM.CKM_SHA3_384_RSA_PKCS_PSS,
            CKM.CKM_SHA3_512_RSA_PKCS_PSS },
        { Struct<CK_TLS_MAC_PARAMS>(nameof(CK_TLS_MAC_PARAMS)), CKM.CKM_TLS_MAC, CKM.CKM_TLS12_MAC },

        // Structs holding pointers.
        { Structs(
                (nameof(CK_GCM_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_PARAMS>()),
                (nameof(CK_GCM_MESSAGE_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_MESSAGE_PARAMS>()),
                (nameof(CK_GCM_WRAP_PARAMS), Pkcs11Marshal.SizeOf<CK_GCM_WRAP_PARAMS>())),
            CKM.CKM_AES_GCM },
        { Structs(
                (nameof(CK_CCM_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_PARAMS>()),
                (nameof(CK_CCM_MESSAGE_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_MESSAGE_PARAMS>()),
                (nameof(CK_CCM_WRAP_PARAMS), Pkcs11Marshal.SizeOf<CK_CCM_WRAP_PARAMS>())),
            CKM.CKM_AES_CCM },
        { Structs(
                (nameof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_PARAMS>()),
                (nameof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>())),
            CKM.CKM_CHACHA20_POLY1305, CKM.CKM_SALSA20_POLY1305 },
        { Struct<CK_CHACHA20_PARAMS>(nameof(CK_CHACHA20_PARAMS)), CKM.CKM_CHACHA20 },
        { Struct<CK_SALSA20_PARAMS>(nameof(CK_SALSA20_PARAMS)), CKM.CKM_SALSA20 },
        { Struct<CK_RSA_PKCS_OAEP_PARAMS>(nameof(CK_RSA_PKCS_OAEP_PARAMS)), CKM.CKM_RSA_PKCS_OAEP },
        { Struct<CK_RSA_AES_KEY_WRAP_PARAMS>(nameof(CK_RSA_AES_KEY_WRAP_PARAMS)), CKM.CKM_RSA_AES_KEY_WRAP },
        { Struct<CK_ECDH1_DERIVE_PARAMS>(nameof(CK_ECDH1_DERIVE_PARAMS)),
            CKM.CKM_ECDH1_DERIVE, CKM.CKM_ECDH1_COFACTOR_DERIVE },
        { Struct<CK_ECMQV_DERIVE_PARAMS>(nameof(CK_ECMQV_DERIVE_PARAMS)), CKM.CKM_ECMQV_DERIVE },
        { Struct<CK_ECDH_AES_KEY_WRAP_PARAMS>(nameof(CK_ECDH_AES_KEY_WRAP_PARAMS)),
            CKM.CKM_ECDH_AES_KEY_WRAP, CKM.CKM_ECDH_COF_AES_KEY_WRAP, CKM.CKM_ECDH_X_AES_KEY_WRAP },
        { Struct<CK_X9_42_DH1_DERIVE_PARAMS>(nameof(CK_X9_42_DH1_DERIVE_PARAMS)), CKM.CKM_X9_42_DH_DERIVE },
        { Struct<CK_X9_42_DH2_DERIVE_PARAMS>(nameof(CK_X9_42_DH2_DERIVE_PARAMS)), CKM.CKM_X9_42_DH_HYBRID_DERIVE },
        { Struct<CK_X9_42_MQV_DERIVE_PARAMS>(nameof(CK_X9_42_MQV_DERIVE_PARAMS)), CKM.CKM_X9_42_MQV_DERIVE },
        { Struct<CK_KEA_DERIVE_PARAMS>(nameof(CK_KEA_DERIVE_PARAMS)), CKM.CKM_KEA_DERIVE, CKM.CKM_KEA_KEY_DERIVE },
        { Struct<CK_DSA_PARAMETER_GEN_PARAM>(nameof(CK_DSA_PARAMETER_GEN_PARAM)),
            CKM.CKM_DSA_PROBABILISTIC_PARAMETER_GEN, CKM.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN, CKM.CKM_DSA_FIPS_G_GEN },
        { Struct<CK_RC5_CBC_PARAMS>(nameof(CK_RC5_CBC_PARAMS)), CKM.CKM_RC5_CBC, CKM.CKM_RC5_CBC_PAD },
        { Struct<CK_DES_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_DES_CBC_ENCRYPT_DATA_PARAMS)),
            CKM.CKM_DES_CBC_ENCRYPT_DATA, CKM.CKM_DES3_CBC_ENCRYPT_DATA },
        { Struct<CK_AES_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)),
            CKM.CKM_AES_CBC_ENCRYPT_DATA },
        { Struct<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)),
            CKM.CKM_ARIA_CBC_ENCRYPT_DATA },
        { Struct<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)),
            CKM.CKM_CAMELLIA_CBC_ENCRYPT_DATA },
        { Struct<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>(nameof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS)),
            CKM.CKM_SEED_CBC_ENCRYPT_DATA },
        { Struct<CK_KEY_DERIVATION_STRING_DATA>(nameof(CK_KEY_DERIVATION_STRING_DATA)),
            CKM.CKM_DES_ECB_ENCRYPT_DATA, CKM.CKM_DES3_ECB_ENCRYPT_DATA, CKM.CKM_AES_ECB_ENCRYPT_DATA,
            CKM.CKM_ARIA_ECB_ENCRYPT_DATA, CKM.CKM_CAMELLIA_ECB_ENCRYPT_DATA, CKM.CKM_SEED_ECB_ENCRYPT_DATA,
            CKM.CKM_CONCATENATE_BASE_AND_DATA, CKM.CKM_CONCATENATE_DATA_AND_BASE, CKM.CKM_XOR_BASE_AND_DATA },
        { Struct<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>(nameof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)),
            CKM.CKM_SKIPJACK_PRIVATE_WRAP },
        { Struct<CK_SKIPJACK_RELAYX_PARAMS>(nameof(CK_SKIPJACK_RELAYX_PARAMS)), CKM.CKM_SKIPJACK_RELAYX },
        { Struct<CK_PBE_PARAMS>(nameof(CK_PBE_PARAMS)),
            CKM.CKM_PBE_MD2_DES_CBC, CKM.CKM_PBE_MD5_DES_CBC, CKM.CKM_PBE_MD5_CAST_CBC, CKM.CKM_PBE_MD5_CAST3_CBC,
            CKM.CKM_PBE_MD5_CAST5_CBC, CKM.CKM_PBE_MD5_CAST128_CBC, CKM.CKM_PBE_SHA1_CAST5_CBC,
            CKM.CKM_PBE_SHA1_CAST128_CBC, CKM.CKM_PBE_SHA1_RC4_128, CKM.CKM_PBE_SHA1_RC4_40,
            CKM.CKM_PBE_SHA1_DES3_EDE_CBC, CKM.CKM_PBE_SHA1_DES2_EDE_CBC, CKM.CKM_PBE_SHA1_RC2_128_CBC,
            CKM.CKM_PBE_SHA1_RC2_40_CBC, CKM.CKM_PBA_SHA1_WITH_SHA1_HMAC },
        { Structs(
                (nameof(CK_PKCS5_PBKD2_PARAMS2), Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS2>()),
                (nameof(CK_PKCS5_PBKD2_PARAMS), Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS>())),
            CKM.CKM_PKCS5_PBKD2 },
        { Struct<CK_KEY_WRAP_SET_OAEP_PARAMS>(nameof(CK_KEY_WRAP_SET_OAEP_PARAMS)), CKM.CKM_KEY_WRAP_SET_OAEP },
        { Struct<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)),
            CKM.CKM_SSL3_MASTER_KEY_DERIVE, CKM.CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM.CKM_TLS_MASTER_KEY_DERIVE,
            CKM.CKM_TLS_MASTER_KEY_DERIVE_DH },
        { Struct<CK_SSL3_KEY_MAT_PARAMS>(nameof(CK_SSL3_KEY_MAT_PARAMS)),
            CKM.CKM_SSL3_KEY_AND_MAC_DERIVE, CKM.CKM_TLS_KEY_AND_MAC_DERIVE },
        { Struct<CK_TLS_PRF_PARAMS>(nameof(CK_TLS_PRF_PARAMS)), CKM.CKM_TLS_PRF },
        { Struct<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS)),
            CKM.CKM_TLS12_MASTER_KEY_DERIVE, CKM.CKM_TLS12_MASTER_KEY_DERIVE_DH },
        { Struct<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS)),
            CKM.CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, CKM.CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH },
        // PKCS#11 v3.2 names CK_TLS12_KEY_MAT_PARAMS for these in the header and in one place in the text,
        // and CK_SSL3_KEY_MAT_PARAMS in another, so either is taken.
        { Structs(
                (nameof(CK_TLS12_KEY_MAT_PARAMS), Pkcs11Marshal.SizeOf<CK_TLS12_KEY_MAT_PARAMS>()),
                (nameof(CK_SSL3_KEY_MAT_PARAMS), Pkcs11Marshal.SizeOf<CK_SSL3_KEY_MAT_PARAMS>())),
            CKM.CKM_TLS12_KEY_AND_MAC_DERIVE, CKM.CKM_TLS12_KEY_SAFE_DERIVE },
        { Struct<CK_TLS_KDF_PARAMS>(nameof(CK_TLS_KDF_PARAMS)), CKM.CKM_TLS_KDF, CKM.CKM_TLS12_KDF },
        { Struct<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>(nameof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)),
            CKM.CKM_WTLS_MASTER_KEY_DERIVE, CKM.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC },
        { Struct<CK_WTLS_PRF_PARAMS>(nameof(CK_WTLS_PRF_PARAMS)), CKM.CKM_WTLS_PRF },
        { Struct<CK_WTLS_KEY_MAT_PARAMS>(nameof(CK_WTLS_KEY_MAT_PARAMS)),
            CKM.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE, CKM.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE },
        { Struct<CK_CMS_SIG_PARAMS>(nameof(CK_CMS_SIG_PARAMS)), CKM.CKM_CMS_SIG },
        { Struct<CK_KIP_PARAMS>(nameof(CK_KIP_PARAMS)), CKM.CKM_KIP_DERIVE, CKM.CKM_KIP_WRAP, CKM.CKM_KIP_MAC },
        { OptionalStruct<CK_OTP_PARAMS>(nameof(CK_OTP_PARAMS)), CKM.CKM_SECURID, CKM.CKM_HOTP, CKM.CKM_ACTI },
        { Struct<CK_GOSTR3410_KEY_WRAP_PARAMS>(nameof(CK_GOSTR3410_KEY_WRAP_PARAMS)), CKM.CKM_GOSTR3410_KEY_WRAP },
        { Struct<CK_GOSTR3410_DERIVE_PARAMS>(nameof(CK_GOSTR3410_DERIVE_PARAMS)), CKM.CKM_GOSTR3410_DERIVE },
        { Struct<CK_SP800_108_KDF_PARAMS>(nameof(CK_SP800_108_KDF_PARAMS)),
            CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF },
        { Struct<CK_SP800_108_FEEDBACK_KDF_PARAMS>(nameof(CK_SP800_108_FEEDBACK_KDF_PARAMS)),
            CKM.CKM_SP800_108_FEEDBACK_KDF },
        { Struct<CK_X3DH_INITIATE_PARAMS>(nameof(CK_X3DH_INITIATE_PARAMS)), CKM.CKM_X3DH_INITIALIZE },
        { Struct<CK_X3DH_RESPOND_PARAMS>(nameof(CK_X3DH_RESPOND_PARAMS)), CKM.CKM_X3DH_RESPOND },
        { Struct<CK_X2RATCHET_INITIALIZE_PARAMS>(nameof(CK_X2RATCHET_INITIALIZE_PARAMS)),
            CKM.CKM_X2RATCHET_INITIALIZE },
        { Struct<CK_X2RATCHET_RESPOND_PARAMS>(nameof(CK_X2RATCHET_RESPOND_PARAMS)), CKM.CKM_X2RATCHET_RESPOND },
        { Struct<CK_HKDF_PARAMS>(nameof(CK_HKDF_PARAMS)), CKM.CKM_HKDF_DERIVE, CKM.CKM_HKDF_DATA },
        { Struct<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>(nameof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS)),
            CKM.CKM_IKE2_PRF_PLUS_DERIVE },
        { Struct<CK_IKE_PRF_DERIVE_PARAMS>(nameof(CK_IKE_PRF_DERIVE_PARAMS)), CKM.CKM_IKE_PRF_DERIVE },
        { Struct<CK_IKE1_PRF_DERIVE_PARAMS>(nameof(CK_IKE1_PRF_DERIVE_PARAMS)), CKM.CKM_IKE1_PRF_DERIVE },
        { Struct<CK_IKE1_EXTENDED_DERIVE_PARAMS>(nameof(CK_IKE1_EXTENDED_DERIVE_PARAMS)),
            CKM.CKM_IKE1_EXTENDED_DERIVE },
        { OptionalStruct<CK_EDDSA_PARAMS>(nameof(CK_EDDSA_PARAMS)), CKM.CKM_EDDSA },
        { OptionalStruct<CK_SIGN_ADDITIONAL_CONTEXT>(nameof(CK_SIGN_ADDITIONAL_CONTEXT)),
            CKM.CKM_ML_DSA, CKM.CKM_SLH_DSA, CKM.CKM_HASH_ML_DSA_SHA224, CKM.CKM_HASH_ML_DSA_SHA256,
            CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_HASH_ML_DSA_SHA512, CKM.CKM_HASH_ML_DSA_SHA3_224,
            CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_HASH_ML_DSA_SHA3_512,
            CKM.CKM_HASH_ML_DSA_SHAKE128, CKM.CKM_HASH_ML_DSA_SHAKE256, CKM.CKM_HASH_SLH_DSA_SHA224,
            CKM.CKM_HASH_SLH_DSA_SHA256, CKM.CKM_HASH_SLH_DSA_SHA384, CKM.CKM_HASH_SLH_DSA_SHA512,
            CKM.CKM_HASH_SLH_DSA_SHA3_224, CKM.CKM_HASH_SLH_DSA_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_384,
            CKM.CKM_HASH_SLH_DSA_SHA3_512, CKM.CKM_HASH_SLH_DSA_SHAKE128, CKM.CKM_HASH_SLH_DSA_SHAKE256 },
        { Struct<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(nameof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)),
            CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_SLH_DSA },
    }.ToFrozenDictionary();

    /// <summary>The rule for <paramref name="type"/>'s parameter, or <see langword="null"/> when it has none.</summary>
    internal static Rule? For(CKM type) => Rules.TryGetValue(type, out Rule rule) ? rule : null;

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

    /// <summary>The rules by mechanism, written as groups of mechanisms that share one.</summary>
    private sealed class RuleTable : IEnumerable<KeyValuePair<CKM, Rule>>
    {
        private readonly Dictionary<CKM, Rule> _rules = [];

        // The enum names some mechanisms twice (CKM_CAST5_CBC is CKM_CAST128_CBC), so a value repeated
        // within a group is the same mechanism; one already in an earlier group is a mistake in the table.
        public void Add(Rule rule, params CKM[] types)
        {
            foreach (CKM type in types.Distinct())
            {
                if (!_rules.TryAdd(type, rule))
                    throw new InvalidOperationException($"{type} has more than one parameter rule.");
            }
        }

        public IEnumerator<KeyValuePair<CKM, Rule>> GetEnumerator() => _rules.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
