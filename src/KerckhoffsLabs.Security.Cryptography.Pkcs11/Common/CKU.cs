using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Types of Cryptoki users
/// </summary>
public enum CKU : uint
{
    /// <summary>
    /// Security Officer
    /// </summary>
    CKU_SO = 0,

    /// <summary>
    /// Normal user
    /// </summary>
    CKU_USER = 1,

    /// <summary>
    /// Context specific
    /// </summary>
    CKU_CONTEXT_SPECIFIC = 2
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKUExtensions
{
    /// <summary>Converts <see cref="CKU"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKU value) => (NativeCULong)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKU"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKU ToCKU(this NativeCULong value)
    {
        CKU result = (CKU)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKU), (ulong)value);
        return result;
    }
}
