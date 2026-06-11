using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Mask generation functions
/// </summary>
public enum CKG : uint
{
    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-1 digest algorithm
    /// </summary>
    CKG_MGF1_SHA1 = 0x00000001,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-256 digest algorithm
    /// </summary>
    CKG_MGF1_SHA256 = 0x00000002,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-384 digest algorithm
    /// </summary>
    CKG_MGF1_SHA384 = 0x00000003,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-512 digest algorithm
    /// </summary>
    CKG_MGF1_SHA512 = 0x00000004,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-224 digest algorithm
    /// </summary>
    CKG_MGF1_SHA224 = 0x00000005,

    /// <summary>
    /// Mask Generation Function with SHA3-224 digest algorithm (PKCS#11 v3.0)
    /// </summary>
    CKG_MGF1_SHA3_224 = 0x00000006,

    /// <summary>
    /// Mask Generation Function with SHA3-256 digest algorithm (PKCS#11 v3.0)
    /// </summary>
    CKG_MGF1_SHA3_256 = 0x00000007,

    /// <summary>
    /// Mask Generation Function with SHA3-384 digest algorithm (PKCS#11 v3.0)
    /// </summary>
    CKG_MGF1_SHA3_384 = 0x00000008,

    /// <summary>
    /// Mask Generation Function with SHA3-512 digest algorithm (PKCS#11 v3.0)
    /// </summary>
    CKG_MGF1_SHA3_512 = 0x00000009
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKGExtensions
{
    /// <summary>Converts <see cref="CKG"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKG value) => (NativeCULong)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKG"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKG ToCKG(this NativeCULong value)
    {
        CKG result = (CKG)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKG), (ulong)value);
        return result;
    }
}
