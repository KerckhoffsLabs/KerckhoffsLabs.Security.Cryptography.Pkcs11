using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
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
    /// <summary>Converts <see cref="CKD"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKD value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKD"/>. Use only when the
    /// value is trusted; otherwise prefer <see cref="ToCKDChecked"/>.
    /// </summary>
    public static CKD ToCKD(this NativeCULong value)
    {
        return (CKD)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKD"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKD ToCKDChecked(this NativeCULong value)
    {
        CKD result = (CKD)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKD), (ulong)value);
        return result;
    }
}