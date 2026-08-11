
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Mechanism type
/// </summary>
public enum CKM : uint
{
    /// <summary>
    /// Key pair generation mechanism based on the RSA public-key cryptosystem, as defined in PKCS #1
    /// </summary>
    CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000,

    /// <summary>
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the block formats initially defined in PKCS #1 v1.5.
    /// </summary>
    CKM_RSA_PKCS = 0x00000001,

    /// <summary>
    /// Mechanism for single-part signatures and verification with and without message recovery based on the RSA public-key cryptosystem and the block formats defined in ISO/IEC 9796 and its annex A
    /// </summary>
    CKM_RSA_9796 = 0x00000002,

    /// <summary>
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem ("raw" RSA, as assumed in X.509)
    /// </summary>
    CKM_RSA_X_509 = 0x00000003,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with MD2 mechanism
    /// </summary>
    CKM_MD2_RSA_PKCS = 0x00000004,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with MD5 mechanism
    /// </summary>
    CKM_MD5_RSA_PKCS = 0x00000005,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with SHA-1 mechanism
    /// </summary>
    CKM_SHA1_RSA_PKCS = 0x00000006,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with RIPEMD-128
    /// </summary>
    CKM_RIPEMD128_RSA_PKCS = 0x00000007,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with RIPEMD-160
    /// </summary>
    CKM_RIPEMD160_RSA_PKCS = 0x00000008,

    /// <summary>
    /// The PKCS #1 RSA OAEP mechanism based on the RSA public-key cryptosystem and the OAEP block format defined in PKCS #1
    /// </summary>
    CKM_RSA_PKCS_OAEP = 0x00000009,

    /// <summary>
    /// The X9.31 RSA key pair generation mechanism
    /// </summary>
    CKM_RSA_X9_31_KEY_PAIR_GEN = 0x0000000A,

    /// <summary>
    /// The ANSI X9.31 RSA mechanism
    /// </summary>
    CKM_RSA_X9_31 = 0x0000000B,

    /// <summary>
    /// The ANSI X9.31 RSA signature with SHA-1 mechanism
    /// </summary>
    CKM_SHA1_RSA_X9_31 = 0x0000000C,

    /// <summary>
    /// The PKCS #1 RSA PSS mechanism based on the RSA public-key cryptosystem and the PSS block format defined in PKCS#1
    /// </summary>
    CKM_RSA_PKCS_PSS = 0x0000000D,

    /// <summary>
    /// The PKCS #1 RSA PSS signature with SHA-1 mechanism
    /// </summary>
    CKM_SHA1_RSA_PKCS_PSS = 0x0000000E,

    /// <summary>
    /// The DSA key pair generation mechanism
    /// </summary>
    CKM_DSA_KEY_PAIR_GEN = 0x00000010,

    /// <summary>
    /// The DSA without hashing mechanism
    /// </summary>
    CKM_DSA = 0x00000011,

    /// <summary>
    /// The DSA with SHA-1 mechanism
    /// </summary>
    CKM_DSA_SHA1 = 0x00000012,

    /// <summary>
    /// The DSA with SHA-224 mechanism
    /// </summary>
    CKM_DSA_SHA224 = 0x00000013,

    /// <summary>
    /// The DSA with SHA-256 mechanism
    /// </summary>
    CKM_DSA_SHA256 = 0x00000014,

    /// <summary>
    /// The DSA with SHA-384 mechanism
    /// </summary>
    CKM_DSA_SHA384 = 0x00000015,

    /// <summary>
    /// The DSA with SHA-512 mechanism
    /// </summary>
    CKM_DSA_SHA512 = 0x00000016,

    /// <summary>
    /// The PKCS #3 Diffie-Hellman key pair generation mechanism
    /// </summary>
    CKM_DH_PKCS_KEY_PAIR_GEN = 0x00000020,

    /// <summary>
    /// The PKCS #3 Diffie-Hellman key derivation mechanism
    /// </summary>
    CKM_DH_PKCS_DERIVE = 0x00000021,

    /// <summary>
    /// The X9.42 Diffie-Hellman key pair generation mechanism
    /// </summary>
    CKM_X9_42_DH_KEY_PAIR_GEN = 0x00000030,

    /// <summary>
    /// The X9.42 Diffie-Hellman key derivation mechanism
    /// </summary>
    CKM_X9_42_DH_DERIVE = 0x00000031,

    /// <summary>
    /// The X9.42 Diffie-Hellman hybrid key derivation mechanism
    /// </summary>
    CKM_X9_42_DH_HYBRID_DERIVE = 0x00000032,

    /// <summary>
    /// The X9.42 Diffie-Hellman Menezes-Qu-Vanstone (MQV) key derivation mechanism
    /// </summary>
    CKM_X9_42_MQV_DERIVE = 0x00000033,

    /// <summary>
    /// PKCS #1 v1.5 RSA signature with SHA-256 mechanism
    /// </summary>
    CKM_SHA256_RSA_PKCS = 0x00000040,

    /// <summary>
    /// PKCS #1 v1.5 RSA signature with SHA-384 mechanism
    /// </summary>
    CKM_SHA384_RSA_PKCS = 0x00000041,

    /// <summary>
    /// PKCS #1 v1.5 RSA signature with SHA-512 mechanism
    /// </summary>
    CKM_SHA512_RSA_PKCS = 0x00000042,

    /// <summary>
    /// The PKCS #1 RSA PSS signature with SHA-256 mechanism
    /// </summary>
    CKM_SHA256_RSA_PKCS_PSS = 0x00000043,

    /// <summary>
    /// The PKCS #1 RSA PSS signature with SHA-384 mechanism
    /// </summary>
    CKM_SHA384_RSA_PKCS_PSS = 0x00000044,

    /// <summary>
    /// The PKCS #1 RSA PSS signature with SHA-512 mechanism
    /// </summary>
    CKM_SHA512_RSA_PKCS_PSS = 0x00000045,

    /// <summary>
    /// The PKCS #1 v1.5 RSA signature with SHA-224 mechanism
    /// </summary>
    CKM_SHA224_RSA_PKCS = 0x00000046,

    /// <summary>
    /// The PKCS #1 RSA PSS signature with SHA-224 mechanism
    /// </summary>
    CKM_SHA224_RSA_PKCS_PSS = 0x00000047,

    /// <summary>
    /// The SHA-512/224 digesting mechanism
    /// </summary>
    CKM_SHA512_224 = 0x00000048,

    /// <summary>
    /// Special case of the general-length SHA-512/224-HMAC mechanism
    /// </summary>
    CKM_SHA512_224_HMAC = 0x00000049,

    /// <summary>
    /// The general-length SHA-512/224-HMAC mechanism that uses the HMAC construction, based on the SHA-512/224 hash function
    /// </summary>
    CKM_SHA512_224_HMAC_GENERAL = 0x0000004A,

    /// <summary>
    /// Key derivation based on the SHA-512/224 hash function
    /// </summary>
    CKM_SHA512_224_KEY_DERIVATION = 0x0000004B,

    /// <summary>
    /// The SHA-512/256 digesting mechanism
    /// </summary>
    CKM_SHA512_256 = 0x0000004C,

    /// <summary>
    /// Special case of the general-length SHA-512/256-HMAC mechanism
    /// </summary>
    CKM_SHA512_256_HMAC = 0x0000004D,

    /// <summary>
    /// The general-length SHA-512/256-HMAC mechanism that uses the HMAC construction, based on the SHA-512/256 hash function
    /// </summary>
    CKM_SHA512_256_HMAC_GENERAL = 0x0000004E,

    /// <summary>
    /// Key derivation based on the SHA-512/256 hash function
    /// </summary>
    CKM_SHA512_256_KEY_DERIVATION = 0x0000004F,

    /// <summary>
    /// The SHA-512/t digesting mechanism
    /// </summary>
    CKM_SHA512_T = 0x00000050,

    /// <summary>
    /// Special case of the general-length SHA-512/t-HMAC mechanism
    /// </summary>
    CKM_SHA512_T_HMAC = 0x00000051,

    /// <summary>
    /// The general-length SHA-512/t-HMAC mechanism that uses the HMAC construction, based on the SHA-512/t hash function
    /// </summary>
    CKM_SHA512_T_HMAC_GENERAL = 0x00000052,

    /// <summary>
    /// Key derivation based on the SHA-512/t hash function
    /// </summary>
    CKM_SHA512_T_KEY_DERIVATION = 0x00000053,

    /// <summary>
    /// The RC2 key generation mechanism
    /// </summary>
    CKM_RC2_KEY_GEN = 0x00000100,

    /// <summary>
    /// RC2-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_RC2_ECB = 0x00000101,

    /// <summary>
    /// RC2-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_RC2_CBC = 0x00000102,

    /// <summary>
    /// Special case of general-length RC2-MAC mechanism
    /// </summary>
    CKM_RC2_MAC = 0x00000103,

    /// <summary>
    /// General-length RC2-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_RC2_MAC_GENERAL = 0x00000104,

    /// <summary>
    /// RC2-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_RC2_CBC_PAD = 0x00000105,

    /// <summary>
    /// The RC4 key generation mechanism
    /// </summary>
    CKM_RC4_KEY_GEN = 0x00000110,

    /// <summary>
    /// RC4 encryption mechanism
    /// </summary>
    CKM_RC4 = 0x00000111,

    /// <summary>
    /// Single-length DES key generation mechanism
    /// </summary>
    CKM_DES_KEY_GEN = 0x00000120,

    /// <summary>
    /// DES-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_DES_ECB = 0x00000121,

    /// <summary>
    /// DES-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_DES_CBC = 0x00000122,

    /// <summary>
    /// Special case of general-length DES-MAC mechanism
    /// </summary>
    CKM_DES_MAC = 0x00000123,

    /// <summary>
    /// General-length DES-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_DES_MAC_GENERAL = 0x00000124,

    /// <summary>
    /// DES-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_DES_CBC_PAD = 0x00000125,

    /// <summary>
    /// Double-length DES key generation mechanism
    /// </summary>
    CKM_DES2_KEY_GEN = 0x00000130,

    /// <summary>
    /// Triple-length DES key generation mechanism
    /// </summary>
    CKM_DES3_KEY_GEN = 0x00000131,

    /// <summary>
    /// DES3-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_DES3_ECB = 0x00000132,

    /// <summary>
    /// DES3-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_DES3_CBC = 0x00000133,

    /// <summary>
    /// Special case of general-length DES3-MAC mechanism
    /// </summary>
    CKM_DES3_MAC = 0x00000134,

    /// <summary>
    /// General-length DES3-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_DES3_MAC_GENERAL = 0x00000135,

    /// <summary>
    /// DES3-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_DES3_CBC_PAD = 0x00000136,

    /// <summary>
    /// General-length DES3-CMAC mechanism based on Cipher-based Message Authenticate Code as defined in NIST SP 800-38B and RFC 4493
    /// </summary>
    CKM_DES3_CMAC_GENERAL = 0x00000137,

    /// <summary>
    /// Special case of general-length DES3-CMAC mechanism based on Cipher-based Message Authenticate Code as defined in NIST SP 800-38B and RFC 4493
    /// </summary>
    CKM_DES3_CMAC = 0x00000138,

    /// <summary>
    /// Single-length CDMF key generation mechanism
    /// </summary>
    CKM_CDMF_KEY_GEN = 0x00000140,

    /// <summary>
    /// CDMF-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CDMF_ECB = 0x00000141,

    /// <summary>
    /// CDMF-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CDMF_CBC = 0x00000142,

    /// <summary>
    /// Special case of general-length CDMF-MAC mechanism
    /// </summary>
    CKM_CDMF_MAC = 0x00000143,

    /// <summary>
    /// General-length CDMF-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CDMF_MAC_GENERAL = 0x00000144,

    /// <summary>
    /// CDMF-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CDMF_CBC_PAD = 0x00000145,

    /// <summary>
    /// DES-OFB64 encryption mechanism with output feedback mode (OFB)
    /// </summary>
    CKM_DES_OFB64 = 0x00000150,

    /// <summary>
    /// DES-OFB8 encryption mechanism with output feedback mode (OFB)
    /// </summary>
    CKM_DES_OFB8 = 0x00000151,

    /// <summary>
    /// DES-CFB64 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_DES_CFB64 = 0x00000152,

    /// <summary>
    /// DES-CFB8 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_DES_CFB8 = 0x00000153,

    /// <summary>
    /// The MD2 digesting mechanism
    /// </summary>
    CKM_MD2 = 0x00000200,

    /// <summary>
    /// Special case of the general-length MD2-HMAC mechanism
    /// </summary>
    CKM_MD2_HMAC = 0x00000201,

    /// <summary>
    /// The general-length MD2-HMAC mechanism that uses the HMAC construction, based on the MD2 hash function
    /// </summary>
    CKM_MD2_HMAC_GENERAL = 0x00000202,

    /// <summary>
    /// The MD5 digesting mechanism
    /// </summary>
    CKM_MD5 = 0x00000210,

    /// <summary>
    /// Special case of the general-length MD5-HMAC mechanism
    /// </summary>
    CKM_MD5_HMAC = 0x00000211,

    /// <summary>
    /// The general-length MD5-HMAC mechanism that uses the HMAC construction, based on the MD5 hash function
    /// </summary>
    CKM_MD5_HMAC_GENERAL = 0x00000212,

    /// <summary>
    /// The SHA-1 digesting mechanism
    /// </summary>
    CKM_SHA_1 = 0x00000220,

    /// <summary>
    /// Special case of the general-length SHA1-HMAC mechanism
    /// </summary>
    CKM_SHA_1_HMAC = 0x00000221,

    /// <summary>
    /// The general-length SHA1-HMAC mechanism that uses the HMAC construction, based on the SHA1 hash function
    /// </summary>
    CKM_SHA_1_HMAC_GENERAL = 0x00000222,

    /// <summary>
    /// The RIPE-MD 128 digesting mechanism
    /// </summary>
    CKM_RIPEMD128 = 0x00000230,

    /// <summary>
    /// Special case of the general-length RIPE-MD 128-HMAC mechanism
    /// </summary>
    CKM_RIPEMD128_HMAC = 0x00000231,

    /// <summary>
    ///  The general-length RIPE-MD 128-HMAC mechanism that uses the HMAC construction, based on the RIPE-MD 128 hash function
    /// </summary>
    CKM_RIPEMD128_HMAC_GENERAL = 0x00000232,

    /// <summary>
    /// The RIPE-MD 160 digesting mechanism
    /// </summary>
    CKM_RIPEMD160 = 0x00000240,

    /// <summary>
    /// Special case of the general-length RIPE-MD 160-HMAC mechanism
    /// </summary>
    CKM_RIPEMD160_HMAC = 0x00000241,

    /// <summary>
    ///  The general-length RIPE-MD 160-HMAC mechanism that uses the HMAC construction, based on the RIPE-MD 160 hash function
    /// </summary>
    CKM_RIPEMD160_HMAC_GENERAL = 0x00000242,

    /// <summary>
    /// The SHA-256 digesting mechanism
    /// </summary>
    CKM_SHA256 = 0x00000250,

    /// <summary>
    /// Special case of the general-length SHA-256-HMAC mechanism
    /// </summary>
    CKM_SHA256_HMAC = 0x00000251,

    /// <summary>
    /// The general-length SHA-256-HMAC mechanism that uses the HMAC construction, based on the SHA-256 hash function
    /// </summary>
    CKM_SHA256_HMAC_GENERAL = 0x00000252,

    /// <summary>
    /// The SHA-224 digesting mechanism
    /// </summary>
    CKM_SHA224 = 0x00000255,

    /// <summary>
    /// Special case of the general-length SHA-224-HMAC mechanism
    /// </summary>
    CKM_SHA224_HMAC = 0x00000256,

    /// <summary>
    /// The general-length SHA-224-HMAC mechanism that uses the HMAC construction, based on the SHA-224 hash function
    /// </summary>
    CKM_SHA224_HMAC_GENERAL = 0x00000257,

    /// <summary>
    /// The SHA-384 digesting mechanism
    /// </summary>
    CKM_SHA384 = 0x00000260,

    /// <summary>
    /// Special case of the general-length SHA-384-HMAC mechanism
    /// </summary>
    CKM_SHA384_HMAC = 0x00000261,

    /// <summary>
    /// The general-length SHA-384-HMAC mechanism that uses the HMAC construction, based on the SHA-384 hash function
    /// </summary>
    CKM_SHA384_HMAC_GENERAL = 0x00000262,

    /// <summary>
    /// The SHA-512 digesting mechanism
    /// </summary>
    CKM_SHA512 = 0x00000270,

    /// <summary>
    /// Special case of the general-length SHA-512-HMAC mechanism
    /// </summary>
    CKM_SHA512_HMAC = 0x00000271,

    /// <summary>
    /// The general-length SHA-512-HMAC mechanism that uses the HMAC construction, based on the SHA-512 hash function
    /// </summary>
    CKM_SHA512_HMAC_GENERAL = 0x00000272,

    /// <summary>
    /// Key generation mechanism for the RSA SecurID algorithm
    /// </summary>
    CKM_SECURID_KEY_GEN = 0x00000280,

    /// <summary>
    /// Mechanism for the retrieval and verification of RSA SecurID OTP values
    /// </summary>
    CKM_SECURID = 0x00000282,

    /// <summary>
    /// Key generation mechanism for the HOTP algorithm
    /// </summary>
    CKM_HOTP_KEY_GEN = 0x00000290,

    /// <summary>
    /// Mechanism for the retrieval and verification of HOTP OTP values
    /// </summary>
    CKM_HOTP = 0x00000291,

    /// <summary>
    /// Mechanism for the retrieval and verification of ACTI OTP values
    /// </summary>
    CKM_ACTI = 0x000002A0,

    /// <summary>
    /// Key generation mechanism for the ACTI algorithm
    /// </summary>
    CKM_ACTI_KEY_GEN = 0x000002A1,

    /// <summary>
    /// CAST key generation mechanism
    /// </summary>
    CKM_CAST_KEY_GEN = 0x00000300,

    /// <summary>
    /// CAST-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAST_ECB = 0x00000301,

    /// <summary>
    /// CAST-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAST_CBC = 0x00000302,

    /// <summary>
    /// Special case of general-length CAST-MAC mechanism
    /// </summary>
    CKM_CAST_MAC = 0x00000303,

    /// <summary>
    /// General-length CAST-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CAST_MAC_GENERAL = 0x00000304,

    /// <summary>
    /// CAST-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CAST_CBC_PAD = 0x00000305,

    /// <summary>
    /// CAST3 key generation mechanism
    /// </summary>
    CKM_CAST3_KEY_GEN = 0x00000310,

    /// <summary>
    /// CAST3-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAST3_ECB = 0x00000311,

    /// <summary>
    /// CAST3-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAST3_CBC = 0x00000312,

    /// <summary>
    /// Special case of general-length CAST3-MAC mechanism
    /// </summary>
    CKM_CAST3_MAC = 0x00000313,

    /// <summary>
    /// General-length CAST3-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CAST3_MAC_GENERAL = 0x00000314,

    /// <summary>
    /// CAST3-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CAST3_CBC_PAD = 0x00000315,

    /// <summary>
    /// CAST128 key generation mechanism
    /// </summary>
    CKM_CAST5_KEY_GEN = 0x00000320,

    /// <summary>
    /// CAST128 key generation mechanism
    /// </summary>
    CKM_CAST128_KEY_GEN = 0x00000320,

    /// <summary>
    /// CAST128-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAST5_ECB = 0x00000321,

    /// <summary>
    /// CAST128-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAST128_ECB = 0x00000321,

    /// <summary>
    /// CAST128-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAST5_CBC = 0x00000322,

    /// <summary>
    /// CAST128-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAST128_CBC = 0x00000322,

    /// <summary>
    /// Special case of general-length CAST128-MAC mechanism
    /// </summary>
    CKM_CAST5_MAC = 0x00000323,

    /// <summary>
    /// Special case of general-length CAST128-MAC mechanism
    /// </summary>
    CKM_CAST128_MAC = 0x00000323,

    /// <summary>
    /// General-length CAST128-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CAST5_MAC_GENERAL = 0x00000324,

    /// <summary>
    /// General-length CAST128-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CAST128_MAC_GENERAL = 0x00000324,

    /// <summary>
    /// CAST128-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CAST5_CBC_PAD = 0x00000325,

    /// <summary>
    /// CAST128-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CAST128_CBC_PAD = 0x00000325,

    /// <summary>
    /// RC5 key generation mechanism
    /// </summary>
    CKM_RC5_KEY_GEN = 0x00000330,

    /// <summary>
    /// RC5-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_RC5_ECB = 0x00000331,

    /// <summary>
    /// RC5-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_RC5_CBC = 0x00000332,

    /// <summary>
    /// Special case of general-length RC5-MAC mechanism
    /// </summary>
    CKM_RC5_MAC = 0x00000333,

    /// <summary>
    /// General-length RC5-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_RC5_MAC_GENERAL = 0x00000334,

    /// <summary>
    /// RC5-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_RC5_CBC_PAD = 0x00000335,

    /// <summary>
    /// IDEA key generation mechanism
    /// </summary>
    CKM_IDEA_KEY_GEN = 0x00000340,

    /// <summary>
    /// IDEA-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_IDEA_ECB = 0x00000341,

    /// <summary>
    /// IDEA-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_IDEA_CBC = 0x00000342,

    /// <summary>
    /// Special case of general-length IDEA-MAC mechanism
    /// </summary>
    CKM_IDEA_MAC = 0x00000343,

    /// <summary>
    /// General-length IDEA-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_IDEA_MAC_GENERAL = 0x00000344,

    /// <summary>
    /// IDEA-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_IDEA_CBC_PAD = 0x00000345,

    /// <summary>
    /// The generic secret key generation mechanism
    /// </summary>
    CKM_GENERIC_SECRET_KEY_GEN = 0x00000350,

    /// <summary>
    /// Key derivation mechanism that derives a secret key from the concatenation of two existing secret keys
    /// </summary>
    CKM_CONCATENATE_BASE_AND_KEY = 0x00000360,

    /// <summary>
    /// Key derivation mechanism that derives a secret key by concatenating data onto the end of a specified secret key
    /// </summary>
    CKM_CONCATENATE_BASE_AND_DATA = 0x00000362,

    /// <summary>
    /// Key derivation mechanism that derives a secret key by prepending data to the start of a specified secret key
    /// </summary>
    CKM_CONCATENATE_DATA_AND_BASE = 0x00000363,

    /// <summary>
    /// Key derivation mechanism that 
    /// </summary>
    CKM_XOR_BASE_AND_DATA = 0x00000364,

    /// <summary>
    /// Mechanism which provides the capability of creating one secret key from the bits of another secret key
    /// </summary>
    CKM_EXTRACT_KEY_FROM_KEY = 0x00000365,

    /// <summary>
    /// Mechanism for pre_master key generation in SSL 3.0
    /// </summary>
    CKM_SSL3_PRE_MASTER_KEY_GEN = 0x00000370,

    /// <summary>
    /// Mechanism for master key derivation in SSL 3.0
    /// </summary>
    CKM_SSL3_MASTER_KEY_DERIVE = 0x00000371,

    /// <summary>
    /// Mechanism for key, MAC and IV derivation in SSL 3.0
    /// </summary>
    CKM_SSL3_KEY_AND_MAC_DERIVE = 0x00000372,

    /// <summary>
    /// Mechanism for master key derivation for Diffie-Hellman in SSL 3.0
    /// </summary>
    CKM_SSL3_MASTER_KEY_DERIVE_DH = 0x00000373,

    /// <summary>
    /// Mechanism for pre-master key generation in TLS 1.0,
    /// </summary>
    CKM_TLS_PRE_MASTER_KEY_GEN = 0x00000374,

    /// <summary>
    /// Mechanism for master key derivation in TLS 1.0
    /// </summary>
    CKM_TLS_MASTER_KEY_DERIVE = 0x00000375,

    /// <summary>
    /// Mechanism for key, MAC and IV derivation in TLS 1.0
    /// </summary>
    CKM_TLS_KEY_AND_MAC_DERIVE = 0x00000376,

    /// <summary>
    /// Mechanism for master key derivation for Diffie-Hellman in TLS 1.0
    /// </summary>
    CKM_TLS_MASTER_KEY_DERIVE_DH = 0x00000377,

    /// <summary>
    /// PRF (pseudo random function) in TLS
    /// </summary>
    CKM_TLS_PRF = 0x00000378,

    /// <summary>
    /// Mechanism for MD5 MACing in SSL3.0
    /// </summary>
    CKM_SSL3_MD5_MAC = 0x00000380,

    /// <summary>
    /// Mechanism for SHA-1 MACing in SSL3.0
    /// </summary>
    CKM_SSL3_SHA1_MAC = 0x00000381,

    /// <summary>
    /// MD5 key derivation mechanism
    /// </summary>
    CKM_MD5_KEY_DERIVATION = 0x00000390,

    /// <summary>
    /// MD2 key derivation mechanism
    /// </summary>
    CKM_MD2_KEY_DERIVATION = 0x00000391,

    /// <summary>
    /// SHA-1 key derivation mechanism
    /// </summary>
    CKM_SHA1_KEY_DERIVATION = 0x00000392,

    /// <summary>
    /// SHA-256 key derivation mechanism
    /// </summary>
    CKM_SHA256_KEY_DERIVATION = 0x00000393,

    /// <summary>
    /// SHA-384 key derivation mechanism
    /// </summary>
    CKM_SHA384_KEY_DERIVATION = 0x00000394,

    /// <summary>
    /// SHA-512 key derivation mechanism
    /// </summary>
    CKM_SHA512_KEY_DERIVATION = 0x00000395,

    /// <summary>
    /// SHA-224 key derivation mechanism
    /// </summary>
    CKM_SHA224_KEY_DERIVATION = 0x00000396,

    /// <summary>
    /// MD2-PBE for DES-CBC mechanism used for generating a DES secret key and an IV from a password and a salt value by using the MD2 digest algorithm and an iteration count. This functionality is defined in PKCS#5 as PBKDF1.
    /// </summary>
    CKM_PBE_MD2_DES_CBC = 0x000003A0,

    /// <summary>
    /// MD5-PBE for DES-CBC mechanism used for generating a DES secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count. This functionality is defined in PKCS#5 as PBKDF1.
    /// </summary>
    CKM_PBE_MD5_DES_CBC = 0x000003A1,

    /// <summary>
    /// MD5-PBE for CAST-CBC mechanism used for generating a CAST secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_MD5_CAST_CBC = 0x000003A2,

    /// <summary>
    /// MD5-PBE for CAST3-CBC mechanism used for generating a CAST3 secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_MD5_CAST3_CBC = 0x000003A3,

    /// <summary>
    /// MD5-PBE for CAST128-CBC (CAST5-CBC) mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_MD5_CAST5_CBC = 0x000003A4,

    /// <summary>
    /// MD5-PBE for CAST128-CBC mechanism used for generating a CAST128 secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_MD5_CAST128_CBC = 0x000003A4,

    /// <summary>
    /// SHA-1-PBE for CAST128-CBC (CAST5-CBC) mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_CAST5_CBC = 0x000003A5,

    /// <summary>
    /// SHA-1-PBE for CAST128-CBC mechanism used for generating a CAST128 secret key and an IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_CAST128_CBC = 0x000003A5,

    /// <summary>
    /// SHA-1-PBE for 128-bit RC4 mechanism used for generating a 128-bit RC4 secret key from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_RC4_128 = 0x000003A6,

    /// <summary>
    /// SHA-1-PBE for 40-bit RC4 mechanism used for generating a 40-bit RC4 secret key from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_RC4_40 = 0x000003A7,

    /// <summary>
    /// SHA-1-PBE for 3-key triple-DES-CBC mechanism used for generating a 3-key triple-DES secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_DES3_EDE_CBC = 0x000003A8,

    /// <summary>
    /// SHA-1-PBE for 2-key triple-DES-CBC mechanism used for generating a 2-key triple-DES secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_DES2_EDE_CBC = 0x000003A9,

    /// <summary>
    /// SHA-1-PBE for 128-bit RC2-CBC mechanism used for generating a 128-bit RC2 secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_RC2_128_CBC = 0x000003AA,

    /// <summary>
    /// SHA-1-PBE for 40-bit RC2-CBC mechanism used for generating a 40-bit RC2 secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
    /// </summary>
    CKM_PBE_SHA1_RC2_40_CBC = 0x000003AB,

    /// <summary>
    /// PKCS #5 PBKDF2 key generation mechanism used for generating a secret key from a password and a salt value
    /// </summary>
    CKM_PKCS5_PBKD2 = 0x000003B0,

    /// <summary>
    /// SHA-1-PBA for SHA-1-HMAC mechanism used for generating a 160-bit generic secret key from a password and a salt value by using the SHA-1 digest algorithm and an iteration count
    /// </summary>
    CKM_PBA_SHA1_WITH_SHA1_HMAC = 0x000003C0,

    /// <summary>
    /// Mechanism for pre-master secret key generation for the RSA key exchange suite in WTLS
    /// </summary>
    CKM_WTLS_PRE_MASTER_KEY_GEN = 0x000003D0,

    /// <summary>
    /// Mechanism for master secret derivation in WTLS
    /// </summary>
    CKM_WTLS_MASTER_KEY_DERIVE = 0x000003D1,

    /// <summary>
    /// Mechanism for master secret derivation for Diffie-Hellman and Elliptic Curve Cryptography in WTLS
    /// </summary>
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2,

    /// <summary>
    /// PRF (pseudo random function) in WTLS
    /// </summary>
    CKM_WTLS_PRF = 0x000003D3,

    /// <summary>
    /// Mechanism for server key, MAC and IV derivation in WTLS
    /// </summary>
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4,

    /// <summary>
    /// Mechanism for client key, MAC and IV derivation in WTLS
    /// </summary>
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5,

    /// <summary>
    /// Mechanism is defined in PKCS#11 v2.40e1 headers but the description is not present in the specification
    /// </summary>
    CKM_TLS10_MAC_SERVER = 0x000003D6, // TODO - Fix description when fixed in PKCS#11 specification

    /// <summary>
    /// Mechanism is defined in PKCS#11 v2.40e1 headers but the description is not present in the specification
    /// </summary>
    CKM_TLS10_MAC_CLIENT = 0x000003D7, // TODO - Fix description when fixed in PKCS#11 specification

    /// <summary>
    /// Mechanism is defined in PKCS#11 v2.40e1 headers but the description is not present in the specification
    /// </summary>
    CKM_TLS12_MAC = 0x000003D8, // TODO - Fix description when fixed in PKCS#11 specification

    /// <summary>
    /// Mechanism is defined in PKCS#11 v2.40e1 headers but the description is not present in the specification
    /// </summary>
    CKM_TLS12_KDF = 0x000003D9, // TODO - Fix description when fixed in PKCS#11 specification

    /// <summary>
    /// Mechanism for master key derivation in TLS 1.2
    /// </summary>
    CKM_TLS12_MASTER_KEY_DERIVE = 0x000003E0,

    /// <summary>
    /// Mechanism for key, MAC and IV derivation in TLS 1.2
    /// </summary>
    CKM_TLS12_KEY_AND_MAC_DERIVE = 0x000003E1,

    /// <summary>
    /// Mechanism for master key derivation for Diffie-Hellman in TLS 1.2
    /// </summary>
    CKM_TLS12_MASTER_KEY_DERIVE_DH = 0x000003E2,

    /// <summary>
    /// Mechanism that is identical to CKM_TLS12_KEY_AND_MAC_DERIVE except that it shall never produce IV data
    /// </summary>
    CKM_TLS12_KEY_SAFE_DERIVE = 0x000003E3,

    /// <summary>
    /// Mechanism for generation of integrity tags for the TLS "finished" message
    /// </summary>
    CKM_TLS_MAC = 0x000003E4,

    /// <summary>
    /// Mechanism that uses the TLS key material and TLS PRF function to produce additional key material for protocols that want to leverage the TLS key negotiation mechanism
    /// </summary>
    CKM_TLS_KDF = 0x000003E5,

    /// <summary>
    /// The LYNKS key wrapping mechanism
    /// </summary>
    CKM_KEY_WRAP_LYNKS = 0x00000400,

    /// <summary>
    /// The OAEP key wrapping for SET mechanism
    /// </summary>
    CKM_KEY_WRAP_SET_OAEP = 0x00000401,

    /// <summary>
    /// The CMS mechanism
    /// </summary>
    CKM_CMS_SIG = 0x00000500,

    /// <summary>
    /// The CT-KIP key derivation mechanism
    /// </summary>
    CKM_KIP_DERIVE = 0x00000510,

    /// <summary>
    /// The CT-KIP key wrap and unwrap mechanism
    /// </summary>
    CKM_KIP_WRAP = 0x00000511,

    /// <summary>
    /// The CT-KIP signature (MAC) mechanism
    /// </summary>
    CKM_KIP_MAC = 0x00000512,

    /// <summary>
    /// The Camellia key generation mechanism
    /// </summary>
    CKM_CAMELLIA_KEY_GEN = 0x00000550,

    /// <summary>
    /// Camellia-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAMELLIA_ECB = 0x00000551,

    /// <summary>
    /// Camellia-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAMELLIA_CBC = 0x00000552,

    /// <summary>
    /// Special case of general-length Camellia-MAC mechanism
    /// </summary>
    CKM_CAMELLIA_MAC = 0x00000553,

    /// <summary>
    /// General-length Camellia-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_CAMELLIA_MAC_GENERAL = 0x00000554,

    /// <summary>
    /// Camellia-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_CAMELLIA_CBC_PAD = 0x00000555,

    /// <summary>
    /// Key derivation mechanism based on Camellia-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_CAMELLIA_ECB_ENCRYPT_DATA = 0x00000556,

    /// <summary>
    /// Key derivation mechanism based on Camellia-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_CAMELLIA_CBC_ENCRYPT_DATA = 0x00000557,

    /// <summary>
    /// Camellia-CTR mechanism for encryption and decryption with CAMELLIA in counter mode
    /// </summary>
    CKM_CAMELLIA_CTR = 0x00000558,

    /// <summary>
    /// The ARIA key generation mechanism
    /// </summary>
    CKM_ARIA_KEY_GEN = 0x00000560,

    /// <summary>
    /// ARIA-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_ARIA_ECB = 0x00000561,

    /// <summary>
    /// ARIA-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_ARIA_CBC = 0x00000562,

    /// <summary>
    /// Special case of general-length ARIA-MAC mechanism
    /// </summary>
    CKM_ARIA_MAC = 0x00000563,

    /// <summary>
    /// General-length ARIA-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_ARIA_MAC_GENERAL = 0x00000564,

    /// <summary>
    /// ARIA-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_ARIA_CBC_PAD = 0x00000565,

    /// <summary>
    /// Key derivation mechanism based on ARIA-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_ARIA_ECB_ENCRYPT_DATA = 0x00000566,

    /// <summary>
    /// Key derivation mechanism based on ARIA-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_ARIA_CBC_ENCRYPT_DATA = 0x00000567,

    /// <summary>
    /// The SEED key generation mechanism
    /// </summary>
    CKM_SEED_KEY_GEN = 0x00000650,

    /// <summary>
    /// SEED-ECB encryption mechanims with electronic codebook mode (ECB)
    /// </summary>
    CKM_SEED_ECB = 0x00000651,

    /// <summary>
    /// SEED-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_SEED_CBC = 0x00000652,

    /// <summary>
    /// Special case of general-length SEED-MAC mechanism
    /// </summary>
    CKM_SEED_MAC = 0x00000653,

    /// <summary>
    /// General-length SEED-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_SEED_MAC_GENERAL = 0x00000654,

    /// <summary>
    /// SEED-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_SEED_CBC_PAD = 0x00000655,

    /// <summary>
    /// Key derivation mechanism based on SEED-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_SEED_ECB_ENCRYPT_DATA = 0x00000656,

    /// <summary>
    /// Key derivation mechanism based on SEED-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_SEED_CBC_ENCRYPT_DATA = 0x00000657,

    /// <summary>
    /// The SKIPJACK key generation mechanism
    /// </summary>
    CKM_SKIPJACK_KEY_GEN = 0x00001000,

    /// <summary>
    /// SKIPJACK-ECB64 mechanism for encryption and decryption with SKIPJACK in 64-bit electronic codebook mode (ECB)
    /// </summary>
    CKM_SKIPJACK_ECB64 = 0x00001001,

    /// <summary>
    /// SKIPJACK-CBC64 mechanism for encryption and decryption with SKIPJACK in 64-bit cipher-block chaining mode (CBC)
    /// </summary>
    CKM_SKIPJACK_CBC64 = 0x00001002,

    /// <summary>
    /// SKIPJACK-OFB64 mechanism for encryption and decryption with SKIPJACK in 64-bit output feedback mode (OFB)
    /// </summary>
    CKM_SKIPJACK_OFB64 = 0x00001003,

    /// <summary>
    /// SKIPJACK-CFB64 mechanism for encryption and decryption with SKIPJACK in 64-bit cipher feedback mode (CFB)
    /// </summary>
    CKM_SKIPJACK_CFB64 = 0x00001004,

    /// <summary>
    /// SKIPJACK-CFB32 mechanism for encryption and decryption with SKIPJACK in 32-bit cipher feedback mode (CFB)
    /// </summary>
    CKM_SKIPJACK_CFB32 = 0x00001005,

    /// <summary>
    /// SKIPJACK-CFB16 mechanism for encryption and decryption with SKIPJACK in 16-bit cipher feedback mode (CFB)
    /// </summary>
    CKM_SKIPJACK_CFB16 = 0x00001006,

    /// <summary>
    /// SKIPJACK-CFB8 mechanism for encryption and decryption with SKIPJACK in 8-bit cipher feedback mode (CFB)
    /// </summary>
    CKM_SKIPJACK_CFB8 = 0x00001007,

    /// <summary>
    /// SKIPJACK mechanism for wrapping and unwrapping of secret keys (MEK)
    /// </summary>
    CKM_SKIPJACK_WRAP = 0x00001008,

    /// <summary>
    /// Mechanism for wrapping and unwrapping KEA and DSA private keys
    /// </summary>
    CKM_SKIPJACK_PRIVATE_WRAP = 0x00001009,

    /// <summary>
    /// Mechanism for "change of wrapping" on a private key which was wrapped with the SKIPJACK-PRIVATE-WRAP mechanism
    /// </summary>
    CKM_SKIPJACK_RELAYX = 0x0000100a,

    /// <summary>
    /// The KEA key pair generation mechanism
    /// </summary>
    CKM_KEA_KEY_PAIR_GEN = 0x00001010,

    /// <summary>
    /// The KEA key derivation mechanism
    /// </summary>
    CKM_KEA_KEY_DERIVE = 0x00001011,

    /// <summary>
    /// The KEA key derivation mechanism
    /// </summary>
    CKM_KEA_DERIVE = 0x00001012,

    /// <summary>
    /// The FORTEZZA timestamp mechanism
    /// </summary>
    CKM_FORTEZZA_TIMESTAMP = 0x00001020,

    /// <summary>
    /// The BATON key generation mechanism
    /// </summary>
    CKM_BATON_KEY_GEN = 0x00001030,

    /// <summary>
    /// BATON-ECB128 mechanism for encryption and decryption with BATON in 128-bit electronic codebook mode (ECB)
    /// </summary>
    CKM_BATON_ECB128 = 0x00001031,

    /// <summary>
    /// BATON-ECB96 mechanism for encryption and decryption with BATON in 96-bit electronic codebook mode (ECB)
    /// </summary>
    CKM_BATON_ECB96 = 0x00001032,

    /// <summary>
    /// BATON-CBC128 mechanism for encryption and decryption with BATON in 128-bit cipher-block chaining mode (CBC)
    /// </summary>
    CKM_BATON_CBC128 = 0x00001033,

    /// <summary>
    /// BATON-COUNTER mechanism encryption and decryption with BATON in counter mode
    /// </summary>
    CKM_BATON_COUNTER = 0x00001034,

    /// <summary>
    /// BATON-SHUFFLE mechanism for encryption and decryption with BATON in shuffle mode
    /// </summary>
    CKM_BATON_SHUFFLE = 0x00001035,

    /// <summary>
    /// BATON mechanism for wrapping and unwrapping of secret keys (MEK)
    /// </summary>
    CKM_BATON_WRAP = 0x00001036,

    /// <summary>
    /// The EC (also related to ECDSA) key pair generation mechanism
    /// </summary>
    CKM_ECDSA_KEY_PAIR_GEN = 0x00001040,

    /// <summary>
    /// The EC (also related to ECDSA) key pair generation mechanism
    /// </summary>
    CKM_EC_KEY_PAIR_GEN = 0x00001040,

    /// <summary>
    /// The ECDSA without hashing mechanism
    /// </summary>
    CKM_ECDSA = 0x00001041,

    /// <summary>
    /// The ECDSA with SHA-1 mechanism
    /// </summary>
    CKM_ECDSA_SHA1 = 0x00001042,

    /// <summary>
    /// The ECDSA with SHA-224 mechanism
    /// </summary>
    CKM_ECDSA_SHA224 = 0x00001043,

    /// <summary>
    /// The ECDSA with SHA-256 mechanism
    /// </summary>
    CKM_ECDSA_SHA256 = 0x00001044,

    /// <summary>
    /// The ECDSA with SHA-384 mechanism
    /// </summary>
    CKM_ECDSA_SHA384 = 0x00001045,

    /// <summary>
    /// The ECDSA with SHA-512 mechanism
    /// </summary>
    CKM_ECDSA_SHA512 = 0x00001046,

    /// <summary>
    /// The elliptic curve Diffie-Hellman (ECDH) key derivation mechanism
    /// </summary>
    CKM_ECDH1_DERIVE = 0x00001050,

    /// <summary>
    /// The elliptic curve Diffie-Hellman (ECDH) with cofactor key derivation mechanism
    /// </summary>
    CKM_ECDH1_COFACTOR_DERIVE = 0x00001051,

    /// <summary>
    /// The elliptic curve Menezes-Qu-Vanstone (ECMQV) key derivation mechanism
    /// </summary>
    CKM_ECMQV_DERIVE = 0x00001052,

    /// <summary>
    /// Mechanism based on the EC public-key cryptosystem and the AES key wrap mechanism
    /// </summary>
    CKM_ECDH_AES_KEY_WRAP = 0x00001053,

    /// <summary>
    /// Mechanism based on the RSA public-key cryptosystem and the AES key wrap mechanism
    /// </summary>
    CKM_RSA_AES_KEY_WRAP = 0x00001054,

    /// <summary>EC Edwards key pair generation (for Ed25519/Ed448 keys). PKCS#11 v3.0 §2.3.</summary>
    CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055,

    /// <summary>EdDSA (Ed25519/Ed448) signing mechanism. PKCS#11 v3.0 §2.3.</summary>
    CKM_EDDSA = 0x00001057,

    /// <summary>
    /// The JUNIPER key generation mechanism
    /// </summary>
    CKM_JUNIPER_KEY_GEN = 0x00001060,

    /// <summary>
    /// JUNIPER-ECB128 mechanism for encryption and decryption with JUNIPER in 128-bit electronic codebook mode (ECB)
    /// </summary>
    CKM_JUNIPER_ECB128 = 0x00001061,

    /// <summary>
    /// JUNIPER-CBC128 mechanism for encryption and decryption with JUNIPER in 128-bit cipher-block chaining mode (CBC)
    /// </summary>
    CKM_JUNIPER_CBC128 = 0x00001062,

    /// <summary>
    /// JUNIPER COUNTER mechanism for encryption and decryption with JUNIPER in counter mode
    /// </summary>
    CKM_JUNIPER_COUNTER = 0x00001063,

    /// <summary>
    /// JUNIPER-SHUFFLE mechanism for encryption and decryption with JUNIPER in shuffle mode
    /// </summary>
    CKM_JUNIPER_SHUFFLE = 0x00001064,

    /// <summary>
    /// The JUNIPER wrap and unwrap mechanism used to wrap and unwrap an MEK
    /// </summary>
    CKM_JUNIPER_WRAP = 0x00001065,

    /// <summary>
    /// The FASTHASH digesting mechanism
    /// </summary>
    CKM_FASTHASH = 0x00001070,

    /// <summary>
    /// The AES key generation mechanism
    /// </summary>
    CKM_AES_KEY_GEN = 0x00001080,

    /// <summary>
    /// AES-ECB encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_AES_ECB = 0x00001081,

    /// <summary>
    /// AES-CBC encryption mechanism with cipher-block chaining mode (CBC)
    /// </summary>
    CKM_AES_CBC = 0x00001082,

    /// <summary>
    /// Special case of general-length AES-MAC mechanism
    /// </summary>
    CKM_AES_MAC = 0x00001083,

    /// <summary>
    /// General-length AES-MAC mechanism based on data authentication as defined in FIPS PUB 113
    /// </summary>
    CKM_AES_MAC_GENERAL = 0x00001084,

    /// <summary>
    /// AES-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_AES_CBC_PAD = 0x00001085,

    /// <summary>
    /// AES-CTR encryption mechanism with AES in counter mode
    /// </summary>
    CKM_AES_CTR = 0x00001086,

    /// <summary>
    /// AES-GCM authenticated encryption
    /// </summary>
    CKM_AES_GCM = 0x00001087,

    /// <summary>
    /// AES-CCM authenticated encryption
    /// </summary>
    CKM_AES_CCM = 0x00001088,

    /// <summary>
    /// AES CBC encryption with Cipher Text Stealing CTS
    /// </summary>
    CKM_AES_CTS = 0x00001089,

    /// <summary>
    /// Special case of general-length AES-CMAC mechanism based on Cipher-based Message Authenticate Code as defined in NIST SP 800-38B and RFC 4493
    /// </summary>
    CKM_AES_CMAC = 0x0000108A,

    /// <summary>
    /// General-length AES-CMAC mechanism based on Cipher-based Message Authenticate Code as defined in NIST SP 800-38B and RFC 4493
    /// </summary>
    CKM_AES_CMAC_GENERAL = 0x0000108B,

    /// <summary>
    /// AES-XCBC-MAC signing and verification mechanism based on NIST AES and RFC 3566
    /// </summary>
    CKM_AES_XCBC_MAC = 0x0000108C,

    /// <summary>
    /// AES-XCBC-MAC-96 signing and verification mechanism based on NIST AES and RFC 3566
    /// </summary>
    CKM_AES_XCBC_MAC_96 = 0x0000108D,

    /// <summary>
    /// AES-GMAC signing and verification mechanism described in NIST SP 800-38D
    /// </summary>
    CKM_AES_GMAC = 0x0000108E,

    /// <summary>
    /// The Blowfish key generation mechanism
    /// </summary>
    CKM_BLOWFISH_KEY_GEN = 0x00001090,

    /// <summary>
    /// Blowfish-CBC mechanism for encryption and decryption; key wrapping; and key unwrapping
    /// </summary>
    CKM_BLOWFISH_CBC = 0x00001091,

    /// <summary>
    /// The Twofish key generation mechanism
    /// </summary>
    CKM_TWOFISH_KEY_GEN = 0x00001092,

    /// <summary>
    /// Twofish-CBC mechanism for encryption and decryption; key wrapping; and key unwrapping
    /// </summary>
    CKM_TWOFISH_CBC = 0x00001093,

    /// <summary>
    /// Blowfish-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_BLOWFISH_CBC_PAD = 0x00001094,

    /// <summary>
    /// Twofish-CBC encryption mechanism with cipher-block chaining mode (CBC) and PKCS#7 padding
    /// </summary>
    CKM_TWOFISH_CBC_PAD = 0x00001095,

    /// <summary>
    /// Key derivation mechanism that uses the result of an DES-ECB encryption operation as the key value
    /// </summary>
    CKM_DES_ECB_ENCRYPT_DATA = 0x00001100,

    /// <summary>
    /// Key derivation mechanism that uses the result of an DES-CBC encryption operation as the key value
    /// </summary>
    CKM_DES_CBC_ENCRYPT_DATA = 0x00001101,

    /// <summary>
    /// Key derivation mechanism that uses the result of an DES3-ECB encryption operation as the key value
    /// </summary>
    CKM_DES3_ECB_ENCRYPT_DATA = 0x00001102,

    /// <summary>
    /// Key derivation mechanism that uses the result of an DES3-CBC encryption operation as the key value
    /// </summary>
    CKM_DES3_CBC_ENCRYPT_DATA = 0x00001103,

    /// <summary>
    /// Key derivation mechanism that uses the result of an AES-ECB encryption operation as the key value
    /// </summary>
    CKM_AES_ECB_ENCRYPT_DATA = 0x00001104,

    /// <summary>
    /// Key derivation mechanism that uses the result of an AES-CBC encryption operation as the key value
    /// </summary>
    CKM_AES_CBC_ENCRYPT_DATA = 0x00001105,

    /// <summary>
    /// GOST R 34.10-2001 key generation
    /// </summary>
    CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200,

    /// <summary>
    /// GOST R 34.10-2001 signing and verification without hashing
    /// </summary>
    CKM_GOSTR3410 = 0x00001201,

    /// <summary>
    /// GOST R 34.10-2001 signing and verification with GOST R 34.11-94 hashing
    /// </summary>
    CKM_GOSTR3410_WITH_GOSTR3411 = 0x00001202,

    /// <summary>
    /// GOST R 34.10-2001 based mechanims for GOST 28147-89 key wrapping
    /// </summary>
    CKM_GOSTR3410_KEY_WRAP = 0x00001203,

    /// <summary>
    /// GOST R 34.10-2001 based key derivation mechanim
    /// </summary>
    CKM_GOSTR3410_DERIVE = 0x00001204,

    /// <summary>
    /// GOST R 34.11-94 digesting mechanism
    /// </summary>
    CKM_GOSTR3411 = 0x00001210,

    /// <summary>
    /// GOST R 34.11-94 based mechanism for HMAC construction
    /// </summary>
    CKM_GOSTR3411_HMAC = 0x00001211,

    /// <summary>
    /// GOST 28147-89 key generation
    /// </summary>
    CKM_GOST28147_KEY_GEN = 0x00001220,

    /// <summary>
    /// GOST 28147-89 encryption mechanism with electronic codebook mode (ECB)
    /// </summary>
    CKM_GOST28147_ECB = 0x00001221,

    /// <summary>
    /// GOST 28147-89 encryption mechanism with with cipher feedback mode (CFB) and additional CBC mode defined in section 2 of RFC 4357
    /// </summary>
    CKM_GOST28147 = 0x00001222,

    /// <summary>
    /// GOST 28147-89-MAC mechanism for data integrity and authentication based on GOST 28147-89 and key meshing algorithms defined in section 2.3 of RFC 4357
    /// </summary>
    CKM_GOST28147_MAC = 0x00001223,

    /// <summary>
    /// GOST 28147-89 based mechanims for GOST 28147-89 key wrapping
    /// </summary>
    CKM_GOST28147_KEY_WRAP = 0x00001224,

    /// <summary>
    /// ChaCha20-Poly1305 AEAD stream cipher and MAC (PKCS#11 v3.0)
    /// </summary>
    CKM_CHACHA20_POLY1305 = 0x00004021,

    /// <summary>
    /// Salsa20-Poly1305 AEAD stream cipher and MAC (PKCS#11 v3.0)
    /// </summary>
    CKM_SALSA20_POLY1305 = 0x00004022,

    /// <summary>
    /// The DSA domain parameter generation mechanism
    /// </summary>
    CKM_DSA_PARAMETER_GEN = 0x00002000,

    /// <summary>
    /// The PKCS #3 Diffie-Hellman domain parameter generation mechanism
    /// </summary>
    CKM_DH_PKCS_PARAMETER_GEN = 0x00002001,

    /// <summary>
    /// The X9.42 Diffie-Hellman domain parameter generation mechanism
    /// </summary>
    CKM_X9_42_DH_PARAMETER_GEN = 0x00002002,

    /// <summary>
    /// The DSA probabilistic domain parameter generation mechanism based on the DSA defined in Appendix A.1.1 of FIPS PUB 186-4
    /// </summary>
    CKM_DSA_PROBABLISTIC_PARAMETER_GEN = 0x00002003,

    /// <summary>
    /// The DSA Shawe-Taylor domain parameter generation mechanism based on the DSA defined in Appendix A.1.2 of FIPS PUB 186-4
    /// </summary>
    CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN = 0x00002004,

    /// <summary>
    /// AES-OFB encryption mechanism with output feedback mode (OFB)
    /// </summary>
    CKM_AES_OFB = 0x00002104,

    /// <summary>
    /// AES-CFB64 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_AES_CFB64 = 0x00002105,

    /// <summary>
    /// AES-CFB8 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_AES_CFB8 = 0x00002106,

    /// <summary>
    /// AES-CFB128 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_AES_CFB128 = 0x00002107,

    /// <summary>
    /// AES-CFB1 encryption mechanism with cipher feedback mode (CFB)
    /// </summary>
    CKM_AES_CFB1 = 0x00002108,

    /// <summary>
    /// AES key wrapping mechanism  without padding
    /// </summary>
    CKM_AES_KEY_WRAP = 0x00002109,

    /// <summary>
    /// AES key wrapping mechanism with padding
    /// </summary>
    CKM_AES_KEY_WRAP_PAD = 0x0000210A,

    /// <summary>
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the block formats initially defined in PKCS#1 v1.5, with additional formatting rules defined in TCPA TPM Specification Version 1.1b
    /// </summary>
    CKM_RSA_PKCS_TPM_1_1 = 0x00004001,

    /// <summary>
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the OAEP block format defined in PKCS #1, with additional formatting defined in TCPA TPM Specification Version 1.1b
    /// </summary>
    CKM_RSA_PKCS_OAEP_TPM_1_1 = 0x00004002,

    /// <summary>
    /// DSA with SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_SHA3_224 = 0x00000018,

    /// <summary>
    /// DSA with SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_SHA3_256 = 0x00000019,

    /// <summary>
    /// DSA with SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_SHA3_384 = 0x0000001A,

    /// <summary>
    /// DSA with SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_SHA3_512 = 0x0000001B,

    /// <summary>
    /// RSA-PKCS#1 v1.5 with SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_RSA_PKCS = 0x00000060,

    /// <summary>
    /// RSA-PKCS#1 v1.5 with SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_RSA_PKCS = 0x00000061,

    /// <summary>
    /// RSA-PKCS#1 v1.5 with SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_RSA_PKCS = 0x00000062,

    /// <summary>
    /// RSA-PSS with SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_RSA_PKCS_PSS = 0x00000063,

    /// <summary>
    /// RSA-PSS with SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_RSA_PKCS_PSS = 0x00000064,

    /// <summary>
    /// RSA-PSS with SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_RSA_PKCS_PSS = 0x00000065,

    /// <summary>
    /// RSA-PKCS#1 v1.5 with SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_RSA_PKCS = 0x00000066,

    /// <summary>
    /// RSA-PSS with SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_RSA_PKCS_PSS = 0x00000067,

    /// <summary>
    /// SHA3-256 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256 = 0x000002B0,

    /// <summary>
    /// HMAC over SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_HMAC = 0x000002B1,

    /// <summary>
    /// HMAC over SHA3-256, truncated to caller-supplied length (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_HMAC_GENERAL = 0x000002B2,

    /// <summary>
    /// Generic secret key generation sized for SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_KEY_GEN = 0x000002B3,

    /// <summary>
    /// SHA3-224 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224 = 0x000002B5,

    /// <summary>
    /// HMAC over SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_HMAC = 0x000002B6,

    /// <summary>
    /// HMAC over SHA3-224, truncated to caller-supplied length (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_HMAC_GENERAL = 0x000002B7,

    /// <summary>
    /// Generic secret key generation sized for SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_KEY_GEN = 0x000002B8,

    /// <summary>
    /// SHA3-384 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384 = 0x000002C0,

    /// <summary>
    /// HMAC over SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_HMAC = 0x000002C1,

    /// <summary>
    /// HMAC over SHA3-384, truncated to caller-supplied length (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_HMAC_GENERAL = 0x000002C2,

    /// <summary>
    /// Generic secret key generation sized for SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_KEY_GEN = 0x000002C3,

    /// <summary>
    /// SHA3-512 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512 = 0x000002D0,

    /// <summary>
    /// HMAC over SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_HMAC = 0x000002D1,

    /// <summary>
    /// HMAC over SHA3-512, truncated to caller-supplied length (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_HMAC_GENERAL = 0x000002D2,

    /// <summary>
    /// Generic secret key generation sized for SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_KEY_GEN = 0x000002D3,

    /// <summary>
    /// Key derivation via SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_256_KEY_DERIVATION = 0x00000397,

    /// <summary>
    /// Key derivation via SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_224_KEY_DERIVATION = 0x00000398,

    /// <summary>
    /// Key derivation via SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_384_KEY_DERIVATION = 0x00000399,

    /// <summary>
    /// Key derivation via SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA3_512_KEY_DERIVATION = 0x0000039A,

    /// <summary>
    /// Key derivation via SHAKE128 XOF (PKCS#11 v3.0)
    /// </summary>
    CKM_SHAKE_128_KEY_DERIVATION = 0x0000039B,

    /// <summary>
    /// Key derivation via SHAKE256 XOF (PKCS#11 v3.0)
    /// </summary>
    CKM_SHAKE_256_KEY_DERIVATION = 0x0000039C,

    /// <summary>Header alias for <see cref="CKM_SHA3_224_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHA3_224_KEY_DERIVE = CKM_SHA3_224_KEY_DERIVATION,

    /// <summary>Header alias for <see cref="CKM_SHA3_256_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHA3_256_KEY_DERIVE = CKM_SHA3_256_KEY_DERIVATION,

    /// <summary>Header alias for <see cref="CKM_SHA3_384_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHA3_384_KEY_DERIVE = CKM_SHA3_384_KEY_DERIVATION,

    /// <summary>Header alias for <see cref="CKM_SHA3_512_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHA3_512_KEY_DERIVE = CKM_SHA3_512_KEY_DERIVATION,

    /// <summary>Header alias for <see cref="CKM_SHAKE_128_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHAKE_128_KEY_DERIVE = CKM_SHAKE_128_KEY_DERIVATION,

    /// <summary>Header alias for <see cref="CKM_SHAKE_256_KEY_DERIVATION"/> (PKCS#11 v3.2 spelling).</summary>
    CKM_SHAKE_256_KEY_DERIVE = CKM_SHAKE_256_KEY_DERIVATION,

    /// <summary>
    /// NIST SP 800-108 counter-mode KDF (PKCS#11 v3.0)
    /// </summary>
    CKM_SP800_108_COUNTER_KDF = 0x000003AC,

    /// <summary>
    /// NIST SP 800-108 feedback-mode KDF (PKCS#11 v3.0)
    /// </summary>
    CKM_SP800_108_FEEDBACK_KDF = 0x000003AD,

    /// <summary>
    /// NIST SP 800-108 double-pipeline KDF (PKCS#11 v3.0)
    /// </summary>
    CKM_SP800_108_DOUBLE_PIPELINE_KDF = 0x000003AE,
    /// <summary>
    /// ECDSA with SHA3-224 (PKCS#11 v3.0)
    /// </summary>
    CKM_ECDSA_SHA3_224 = 0x00001047,

    /// <summary>
    /// ECDSA with SHA3-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_ECDSA_SHA3_256 = 0x00001048,

    /// <summary>
    /// ECDSA with SHA3-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_ECDSA_SHA3_384 = 0x00001049,

    /// <summary>
    /// ECDSA with SHA3-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_ECDSA_SHA3_512 = 0x0000104A,

    /// <summary>
    /// Montgomery-curve (X25519/X448) key pair generation (PKCS#11 v3.0)
    /// </summary>
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN = 0x00001056,

    /// <summary>
    /// AES in XTS mode (PKCS#11 v3.0)
    /// </summary>
    CKM_AES_XTS = 0x00001071,

    /// <summary>
    /// AES-XTS key generation — returns a double-length AES key (PKCS#11 v3.0)
    /// </summary>
    CKM_AES_XTS_KEY_GEN = 0x00001072,

    /// <summary>
    /// EC key-pair generation with extra random bits in the private value (PKCS#11 v3.0)
    /// </summary>
    CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS = 0x0000140B,

    /// <summary>
    /// ChaCha20 key generation (PKCS#11 v3.0)
    /// </summary>
    CKM_CHACHA20_KEY_GEN = 0x00001225,

    /// <summary>
    /// ChaCha20 stream cipher — raw mode, no Poly1305 tag (PKCS#11 v3.0)
    /// </summary>
    CKM_CHACHA20 = 0x00001226,

    /// <summary>
    /// Poly1305 MAC key generation (PKCS#11 v3.0)
    /// </summary>
    CKM_POLY1305_KEY_GEN = 0x00001227,

    /// <summary>
    /// Poly1305 MAC (PKCS#11 v3.0)
    /// </summary>
    CKM_POLY1305 = 0x00001228,

    /// <summary>
    /// DSA domain parameter generation, probabilistic method (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_PROBABILISTIC_PARAMETER_GEN = 0x00002003,

    /// <summary>
    /// DSA generator (g) generation per FIPS 186 (PKCS#11 v3.0)
    /// </summary>
    CKM_DSA_FIPS_G_GEN = 0x00002005,

    /// <summary>
    /// AES Key Wrap with Padding (KWP) per RFC 5649 / NIST SP 800-38F (PKCS#11 v3.0)
    /// </summary>
    CKM_AES_KEY_WRAP_KWP = 0x0000210B,

    /// <summary>
    /// AES Key Wrap with PKCS#7 padding (PKCS#11 v3.0)
    /// </summary>
    CKM_AES_KEY_WRAP_PKCS7 = 0x0000210C,

    /// <summary>
    /// Generic-secret key generation sized for SHA-1 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA_1_KEY_GEN = 0x00004003,

    /// <summary>
    /// Generic-secret key generation sized for SHA-224 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA224_KEY_GEN = 0x00004004,

    /// <summary>
    /// Generic-secret key generation sized for SHA-256 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA256_KEY_GEN = 0x00004005,

    /// <summary>
    /// Generic-secret key generation sized for SHA-384 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA384_KEY_GEN = 0x00004006,

    /// <summary>
    /// Generic-secret key generation sized for SHA-512 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA512_KEY_GEN = 0x00004007,

    /// <summary>
    /// Generic-secret key generation sized for SHA-512/224 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA512_224_KEY_GEN = 0x00004008,

    /// <summary>
    /// Generic-secret key generation sized for SHA-512/256 HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA512_256_KEY_GEN = 0x00004009,

    /// <summary>
    /// Generic-secret key generation sized for truncated SHA-512/T HMAC use (PKCS#11 v3.0)
    /// </summary>
    CKM_SHA512_T_KEY_GEN = 0x0000400A,

    /// <summary>
    /// NULL mechanism — returns input as output (used in some KDF chains) (PKCS#11 v3.0)
    /// </summary>
    CKM_NULL = 0x0000400B,

    /// <summary>
    /// BLAKE2b-160 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_160 = 0x0000400C,

    /// <summary>
    /// HMAC over BLAKE2b-160 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_160_HMAC = 0x0000400D,

    /// <summary>
    /// HMAC over BLAKE2b-160, truncated (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_160_HMAC_GENERAL = 0x0000400E,

    /// <summary>
    /// Key derivation via BLAKE2b-160 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_160_KEY_DERIVE = 0x0000400F,

    /// <summary>
    /// Generic-secret key generation sized for BLAKE2b-160 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_160_KEY_GEN = 0x00004010,

    /// <summary>
    /// BLAKE2b-256 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_256 = 0x00004011,

    /// <summary>
    /// HMAC over BLAKE2b-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_256_HMAC = 0x00004012,

    /// <summary>
    /// HMAC over BLAKE2b-256, truncated (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_256_HMAC_GENERAL = 0x00004013,

    /// <summary>
    /// Key derivation via BLAKE2b-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_256_KEY_DERIVE = 0x00004014,

    /// <summary>
    /// Generic-secret key generation sized for BLAKE2b-256 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_256_KEY_GEN = 0x00004015,

    /// <summary>
    /// BLAKE2b-384 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_384 = 0x00004016,

    /// <summary>
    /// HMAC over BLAKE2b-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_384_HMAC = 0x00004017,

    /// <summary>
    /// HMAC over BLAKE2b-384, truncated (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_384_HMAC_GENERAL = 0x00004018,

    /// <summary>
    /// Key derivation via BLAKE2b-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_384_KEY_DERIVE = 0x00004019,

    /// <summary>
    /// Generic-secret key generation sized for BLAKE2b-384 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_384_KEY_GEN = 0x0000401A,

    /// <summary>
    /// BLAKE2b-512 digest (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_512 = 0x0000401B,

    /// <summary>
    /// HMAC over BLAKE2b-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_512_HMAC = 0x0000401C,

    /// <summary>
    /// HMAC over BLAKE2b-512, truncated (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_512_HMAC_GENERAL = 0x0000401D,

    /// <summary>
    /// Key derivation via BLAKE2b-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_512_KEY_DERIVE = 0x0000401E,

    /// <summary>
    /// Generic-secret key generation sized for BLAKE2b-512 (PKCS#11 v3.0)
    /// </summary>
    CKM_BLAKE2B_512_KEY_GEN = 0x0000401F,

    /// <summary>
    /// Salsa20 stream cipher — raw mode, no Poly1305 tag (PKCS#11 v3.0)
    /// </summary>
    CKM_SALSA20 = 0x00004020,

    /// <summary>
    /// Signal X3DH key-agreement initiator (PKCS#11 v3.0)
    /// </summary>
    CKM_X3DH_INITIALIZE = 0x00004023,

    /// <summary>
    /// Signal X3DH key-agreement responder (PKCS#11 v3.0)
    /// </summary>
    CKM_X3DH_RESPOND = 0x00004024,

    /// <summary>
    /// Signal Double-Ratchet initialization (PKCS#11 v3.0)
    /// </summary>
    CKM_X2RATCHET_INITIALIZE = 0x00004025,

    /// <summary>
    /// Signal Double-Ratchet response (PKCS#11 v3.0)
    /// </summary>
    CKM_X2RATCHET_RESPOND = 0x00004026,

    /// <summary>
    /// Signal Double-Ratchet encrypt (PKCS#11 v3.0)
    /// </summary>
    CKM_X2RATCHET_ENCRYPT = 0x00004027,

    /// <summary>
    /// Signal Double-Ratchet decrypt (PKCS#11 v3.0)
    /// </summary>
    CKM_X2RATCHET_DECRYPT = 0x00004028,

    /// <summary>
    /// XEdDSA signature scheme (Signal protocol) (PKCS#11 v3.0)
    /// </summary>
    CKM_XEDDSA = 0x00004029,

    /// <summary>
    /// HKDF derive to produce a key per RFC 5869 (PKCS#11 v3.0)
    /// </summary>
    CKM_HKDF_DERIVE = 0x0000402A,

    /// <summary>
    /// HKDF derive to produce data (non-key bytes) per RFC 5869 (PKCS#11 v3.0)
    /// </summary>
    CKM_HKDF_DATA = 0x0000402B,

    /// <summary>
    /// HKDF input keying material generation (PKCS#11 v3.0)
    /// </summary>
    CKM_HKDF_KEY_GEN = 0x0000402C,

    /// <summary>
    /// Salsa20 key generation (PKCS#11 v3.0)
    /// </summary>
    CKM_SALSA20_KEY_GEN = 0x0000402D,

    /// <summary>
    /// IKEv2 PRF+ key derivation per RFC 7296 §2.13 (PKCS#11 v3.0)
    /// </summary>
    CKM_IKE2_PRF_PLUS_DERIVE = 0x0000402E,

    /// <summary>
    /// IKE PRF derivation (shared) (PKCS#11 v3.0)
    /// </summary>
    CKM_IKE_PRF_DERIVE = 0x0000402F,

    /// <summary>
    /// IKEv1 PRF key derivation (PKCS#11 v3.0)
    /// </summary>
    CKM_IKE1_PRF_DERIVE = 0x00004030,

    /// <summary>
    /// IKEv1 extended key derivation (PKCS#11 v3.0)
    /// </summary>
    CKM_IKE1_EXTENDED_DERIVE = 0x00004031,

    /// <summary>
    /// HSS hash-based signature key-pair generation per RFC 8554 (PKCS#11 v3.1)
    /// </summary>
    CKM_HSS_KEY_PAIR_GEN = 0x00004032,

    /// <summary>
    /// HSS hash-based signature scheme per RFC 8554 (PKCS#11 v3.1)
    /// </summary>
    CKM_HSS = 0x00004033,

    /// <summary>
    /// ML-KEM (FIPS 203) key-pair generation (PKCS#11 v3.2)
    /// </summary>
    CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000F,

    /// <summary>
    /// ML-KEM (FIPS 203) encapsulation / decapsulation mechanism (PKCS#11 v3.2)
    /// </summary>
    CKM_ML_KEM = 0x00000017,

    /// <summary>
    /// ML-DSA (FIPS 204) key-pair generation (PKCS#11 v3.2)
    /// </summary>
    CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001C,

    /// <summary>
    /// ML-DSA (FIPS 204) signing / verification — pure mode (PKCS#11 v3.2)
    /// </summary>
    CKM_ML_DSA = 0x0000001D,

    /// <summary>
    /// ML-DSA HashML-DSA prehash variant; caller specifies hash via params (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA = 0x0000001F,

    /// <summary>
    /// HashML-DSA with SHA-224 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA224 = 0x00000023,

    /// <summary>
    /// HashML-DSA with SHA-256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA256 = 0x00000024,

    /// <summary>
    /// HashML-DSA with SHA-384 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA384 = 0x00000025,

    /// <summary>
    /// HashML-DSA with SHA-512 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA512 = 0x00000026,

    /// <summary>
    /// HashML-DSA with SHA3-224 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA3_224 = 0x00000027,

    /// <summary>
    /// HashML-DSA with SHA3-256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA3_256 = 0x00000028,

    /// <summary>
    /// HashML-DSA with SHA3-384 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA3_384 = 0x00000029,

    /// <summary>
    /// HashML-DSA with SHA3-512 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHA3_512 = 0x0000002A,

    /// <summary>
    /// HashML-DSA with SHAKE128 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHAKE128 = 0x0000002B,

    /// <summary>
    /// HashML-DSA with SHAKE256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_ML_DSA_SHAKE256 = 0x0000002C,

    /// <summary>
    /// SLH-DSA (FIPS 205, stateless hash-based) key-pair generation (PKCS#11 v3.2)
    /// </summary>
    CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002D,

    /// <summary>
    /// SLH-DSA (FIPS 205) signing / verification — pure mode (PKCS#11 v3.2)
    /// </summary>
    CKM_SLH_DSA = 0x0000002E,

    /// <summary>
    /// HashSLH-DSA prehash variant; caller specifies hash via params (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA = 0x00000034,

    /// <summary>
    /// HashSLH-DSA with SHA-224 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA224 = 0x00000036,

    /// <summary>
    /// HashSLH-DSA with SHA-256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA256 = 0x00000037,

    /// <summary>
    /// HashSLH-DSA with SHA-384 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA384 = 0x00000038,

    /// <summary>
    /// HashSLH-DSA with SHA-512 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA512 = 0x00000039,

    /// <summary>
    /// HashSLH-DSA with SHA3-224 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA3_224 = 0x0000003A,

    /// <summary>
    /// HashSLH-DSA with SHA3-256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA3_256 = 0x0000003B,

    /// <summary>
    /// HashSLH-DSA with SHA3-384 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA3_384 = 0x0000003C,

    /// <summary>
    /// HashSLH-DSA with SHA3-512 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHA3_512 = 0x0000003D,

    /// <summary>
    /// HashSLH-DSA with SHAKE128 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHAKE128 = 0x0000003E,

    /// <summary>
    /// HashSLH-DSA with SHAKE256 prehash (PKCS#11 v3.2)
    /// </summary>
    CKM_HASH_SLH_DSA_SHAKE256 = 0x0000003F,

    /// <summary>
    /// TLS 1.2 extended master key derivation per RFC 7627 (PKCS#11 v3.2)
    /// </summary>
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE = 0x00000056,

    /// <summary>
    /// TLS 1.2 extended master key derivation with DH (PKCS#11 v3.2)
    /// </summary>
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH = 0x00000057,

    /// <summary>
    /// XMSS (RFC 8391) stateful hash-based key-pair generation (PKCS#11 v3.2)
    /// </summary>
    CKM_XMSS_KEY_PAIR_GEN = 0x00004034,

    /// <summary>
    /// XMSSMT multi-tree variant key-pair generation (PKCS#11 v3.2)
    /// </summary>
    CKM_XMSSMT_KEY_PAIR_GEN = 0x00004035,

    /// <summary>
    /// XMSS signing / verification (PKCS#11 v3.2)
    /// </summary>
    CKM_XMSS = 0x00004036,

    /// <summary>
    /// XMSSMT signing / verification (PKCS#11 v3.2)
    /// </summary>
    CKM_XMSSMT = 0x00004037,

    /// <summary>
    /// ECDH-X (Montgomery curve) followed by AES key wrap (PKCS#11 v3.2)
    /// </summary>
    CKM_ECDH_X_AES_KEY_WRAP = 0x00004038,

    /// <summary>
    /// ECDH cofactor variant followed by AES key wrap (PKCS#11 v3.2)
    /// </summary>
    CKM_ECDH_COF_AES_KEY_WRAP = 0x00004039,

    /// <summary>
    /// Mechanism that derives a public key from an existing private key (PKCS#11 v3.2)
    /// </summary>
    CKM_PUB_KEY_FROM_PRIV_KEY = 0x0000403A,

    /// <summary>
    /// Permanently reserved for token vendors
    /// </summary>
    CKM_VENDOR_DEFINED = 0x80000000
}

/// <summary>Conversion helpers between <see cref="CKM"/> and the native <c>CK_ULONG</c> width.</summary>
internal static class CKMExtensions
{
    /// <summary>
    /// Converts CKM to NativeCULong
    /// </summary>
    /// <param name="value">CKM that should be converted</param>
    /// <returns>NativeCULong with value from CKM</returns>
    public static NativeCULong ToCULong(this CKM value) => (NativeCULong)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKM"/>. Deliberately a non-validating
    /// cast, unlike most <c>ToCK*</c> converters: mechanism values read back from native
    /// structures may legally be vendor-defined (≥ <see cref="CKM.CKM_VENDOR_DEFINED"/>) or
    /// newer than this enum, and must round-trip rather than crash the conversion.
    /// </summary>
    public static CKM ToCKM(this NativeCULong value) => (CKM)(ulong)value;
}
