using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Notifications
/// </summary>
public enum CKN : uint
{
    /// <summary>
    /// Cryptoki is surrendering the execution of a function executing in a session so that the application may perform other operations
    /// </summary>
    CKN_SURRENDER = 0,

    /// <summary>
    /// Cryptoki is informing the application that the OTP for a key on a connected token just changed
    /// </summary>
    CKN_OTP_CHANGED = 1
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKNExtensions
{
    /// <summary>Converts <see cref="CKN"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKN value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKN"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKN ToCKN(this NativeCULong value)
    {
        CKN result = (CKN)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKN), (ulong)value);
        return result;
    }
}
