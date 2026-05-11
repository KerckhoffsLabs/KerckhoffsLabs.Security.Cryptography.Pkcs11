using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Pseudo-random functions
/// </summary>
public enum CKP : uint
{
    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-1 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA1 = 0x00000001,

    /// <summary>
    /// PKCS#5 PBKDF2 with GOST R34.11-94 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_GOSTR3411 = 0x00000002,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-224 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA224 = 0x00000003,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-256 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA256 = 0x00000004,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-384 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA384 = 0x00000005,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-512 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA512 = 0x00000006,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-512/224 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA512_224 = 0x00000007,

    /// <summary>
    /// PKCS#5 PBKDF2 with HMAC-SHA-512/256 pseudorandom function
    /// </summary>
    CKP_PKCS5_PBKD2_HMAC_SHA512_256 = 0x00000008
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKPExtensions
{
    /// <summary>
    /// Converts CKP to NativeCULong
    /// </summary>
    /// <param name="value">CKP that should be converted</param>
    /// <returns>NativeCULong with value from CKP</returns>
    public static NativeCULong ToCULong(CKP value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKP
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKP with NativeCULong value</returns>
    public static CKP ToCKP(NativeCULong value)
    {
        return (CKP)value.Value;
    }
}