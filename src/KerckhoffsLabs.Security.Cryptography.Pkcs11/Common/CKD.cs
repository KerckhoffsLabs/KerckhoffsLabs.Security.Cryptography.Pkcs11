using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Key derivation functions
/// </summary>
public enum CKD : uint
{
    /// <summary>
    /// No derivation function
    /// </summary>
    CKD_NULL = 0x00000001,

    /// <summary>
    /// ANSI X9.63 key derivation function based on SHA-1
    /// </summary>
    CKD_SHA1_KDF = 0x00000002,

    /// <summary>
    /// ANSI X9.42 key derivation function based on SHA-1
    /// </summary>
    CKD_SHA1_KDF_ASN1 = 0x00000003,

    /// <summary>
    /// ANSI X9.42 key derivation function based on SHA-1
    /// </summary>
    CKD_SHA1_KDF_CONCATENATE = 0x00000004,

    /// <summary>
    /// ANSI X9.63 key derivation function based on SHA-224
    /// </summary>
    CKD_SHA224_KDF = 0x00000005,

    /// <summary>
    /// ANSI X9.63 key derivation function based on SHA-256
    /// </summary>
    CKD_SHA256_KDF = 0x00000006,

    /// <summary>
    /// ANSI X9.63 key derivation function based on SHA-384
    /// </summary>
    CKD_SHA384_KDF = 0x00000007,

    /// <summary>
    /// ANSI X9.63 key derivation function based on SHA-512
    /// </summary>
    CKD_SHA512_KDF = 0x00000008,

    /// <summary>
    /// CryptoPro KEK Diversification Algorithm described in section 6.5 of RFC 4357 
    /// </summary>
    CKD_CPDIVERSIFY_KDF = 0x00000009,

    /// <summary>ANSI X9.63 KDF with SHA3-224 (PKCS#11 v3.0)</summary>
    CKD_SHA3_224_KDF = 0x0000000A,

    /// <summary>ANSI X9.63 KDF with SHA3-256 (PKCS#11 v3.0)</summary>
    CKD_SHA3_256_KDF = 0x0000000B,

    /// <summary>ANSI X9.63 KDF with SHA3-384 (PKCS#11 v3.0)</summary>
    CKD_SHA3_384_KDF = 0x0000000C,

    /// <summary>ANSI X9.63 KDF with SHA3-512 (PKCS#11 v3.0)</summary>
    CKD_SHA3_512_KDF = 0x0000000D,

    /// <summary>NIST SP 800-56C one-step KDF with SHA-1 (PKCS#11 v3.0)</summary>
    CKD_SHA1_KDF_SP800 = 0x0000000E,

    /// <summary>NIST SP 800-56C one-step KDF with SHA-224 (PKCS#11 v3.0)</summary>
    CKD_SHA224_KDF_SP800 = 0x0000000F,

    /// <summary>NIST SP 800-56C one-step KDF with SHA-256 (PKCS#11 v3.0)</summary>
    CKD_SHA256_KDF_SP800 = 0x00000010,

    /// <summary>NIST SP 800-56C one-step KDF with SHA-384 (PKCS#11 v3.0)</summary>
    CKD_SHA384_KDF_SP800 = 0x00000011,

    /// <summary>NIST SP 800-56C one-step KDF with SHA-512 (PKCS#11 v3.0)</summary>
    CKD_SHA512_KDF_SP800 = 0x00000012,

    /// <summary>NIST SP 800-56C one-step KDF with SHA3-224 (PKCS#11 v3.0)</summary>
    CKD_SHA3_224_KDF_SP800 = 0x00000013,

    /// <summary>NIST SP 800-56C one-step KDF with SHA3-256 (PKCS#11 v3.0)</summary>
    CKD_SHA3_256_KDF_SP800 = 0x00000014,

    /// <summary>NIST SP 800-56C one-step KDF with SHA3-384 (PKCS#11 v3.0)</summary>
    CKD_SHA3_384_KDF_SP800 = 0x00000015,

    /// <summary>NIST SP 800-56C one-step KDF with SHA3-512 (PKCS#11 v3.0)</summary>
    CKD_SHA3_512_KDF_SP800 = 0x00000016,

    /// <summary>ANSI X9.63 KDF with BLAKE2b-160 (PKCS#11 v3.0)</summary>
    CKD_BLAKE2B_160_KDF = 0x00000017,

    /// <summary>ANSI X9.63 KDF with BLAKE2b-256 (PKCS#11 v3.0)</summary>
    CKD_BLAKE2B_256_KDF = 0x00000018,

    /// <summary>ANSI X9.63 KDF with BLAKE2b-384 (PKCS#11 v3.0)</summary>
    CKD_BLAKE2B_384_KDF = 0x00000019,

    /// <summary>ANSI X9.63 KDF with BLAKE2b-512 (PKCS#11 v3.0)</summary>
    CKD_BLAKE2B_512_KDF = 0x0000001A
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKDExtensions
{
    /// <summary>Converts <see cref="CKD"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKD value) => (NativeCULong)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKD"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKD ToCKD(this NativeCULong value)
    {
        CKD result = (CKD)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKD), (ulong)value);
        return result;
    }
}
