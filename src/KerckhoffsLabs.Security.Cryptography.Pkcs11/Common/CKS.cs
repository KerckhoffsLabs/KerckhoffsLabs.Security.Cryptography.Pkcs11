using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Session States
/// </summary>
public enum CKS : uint
{
    /// <summary>
    /// The application has opened a read-only session. The application has read-only access to public token objects and read/write access to public session objects.
    /// </summary>
    CKS_RO_PUBLIC_SESSION = 0,

    /// <summary>
    /// The normal user has been authenticated to the token. The application has read-only access to all token objects (public or private) and read/write access to all session objects (public or private).
    /// </summary>
    CKS_RO_USER_FUNCTIONS = 1,

    /// <summary>
    /// The application has opened a read/write session. The application has read/write access to all public objects.
    /// </summary>
    CKS_RW_PUBLIC_SESSION = 2,

    /// <summary>
    /// The normal user has been authenticated to the token. The application has read/write access to all objects.
    /// </summary>
    CKS_RW_USER_FUNCTIONS = 3,

    /// <summary>
    /// The Security Officer has been authenticated to the token. The application has read/write access only to public objects on the token, not to private objects. The SO can set the normal user's PIN.
    /// </summary>
    CKS_RW_SO_FUNCTIONS = 4
}

/// <summary>
/// Session validation flags type (PKCS#11 v3.2 <c>CK_SESSION_VALIDATION_FLAGS_TYPE</c>). Selects
/// which set of validation flags <c>C_GetSessionValidationFlags</c> returns for a session.
/// </summary>
public enum CksValidationFlagsType : uint
{
    /// <summary>
    /// Request the flags describing whether the session's most recent validatable operation
    /// completed successfully within the active validation profile. Each set bit in the returned
    /// flags corresponds to a validation authority (cf. <see cref="CKA.CKA_VALIDATION_FLAG"/>) that
    /// accepted the operation.
    /// </summary>
    CKS_LAST_VALIDATION_OK = 1,
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKSExtensions
{
    /// <summary>Converts <see cref="CKS"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKS value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKS"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKS ToCKS(this NativeCULong value)
    {
        CKS result = (CKS)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKS), (ulong)value);
        return result;
    }
}
