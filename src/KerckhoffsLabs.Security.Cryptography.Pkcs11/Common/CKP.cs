using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

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
    /// <summary>Converts <see cref="CKP"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKP value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKP"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKP ToCKP(this NativeCULong value)
    {
        CKP result = (CKP)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKP), (ulong)value);
        return result;
    }
}
