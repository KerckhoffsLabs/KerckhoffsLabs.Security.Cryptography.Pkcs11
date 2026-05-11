using System.Runtime.InteropServices;

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
    CKD_CPDIVERSIFY_KDF = 0x00000009
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKDExtensions
{
    /// <summary>
    /// Converts CKD to NativeCULong
    /// </summary>
    /// <param name="value">CKD that should be converted</param>
    /// <returns>NativeCULong with value from CKD</returns>
    public static NativeCULong ToCULong(CKD value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKD
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKD with NativeCULong value</returns>
    public static CKD ToCKD(NativeCULong value)
    {
        return (CKD)value.Value;
    }
}