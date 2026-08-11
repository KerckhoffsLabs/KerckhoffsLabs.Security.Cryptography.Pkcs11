using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// General PKCS#11 constants, grouped by the spec category they belong to.
/// </summary>
public static class CK
{
    #region General sentinels

    /// <summary>
    /// The following value is always invalid if used as a session handle or object handle
    /// </summary>
    public const ulong CK_INVALID_HANDLE = 0;

    /// <summary>
    /// Token and/or library is unable or unwilling to provide information.
    /// </summary>
    /// <remarks>
    /// The spec defines this as all bits set in a <c>CK_ULONG</c>, and <c>CK_ULONG</c> is not the
    /// same width everywhere: it is 32-bit on Windows and pointer-sized elsewhere. Values read back
    /// from a token widen to <see cref="ulong"/> unchanged, so the sentinel to compare them against
    /// is <c>0xFFFFFFFF</c> on Windows and <c>0xFFFFFFFFFFFFFFFF</c> on a 64-bit Unix — which is why
    /// this is the one constant here that cannot be a compile-time <c>const</c>. Prefer
    /// <see cref="IsCkInformationUnavailable(ulong)"/> over comparing by hand.
    /// </remarks>
    public static readonly ulong CK_UNAVAILABLE_INFORMATION =
        UnmanagedMemory.NativeULongSize == sizeof(uint) ? uint.MaxValue : ulong.MaxValue;

    /// <summary>
    /// Checks whether provided number has value of CK_UNAVAILABLE_INFORMATION constant
    /// </summary>
    /// <param name="value">Number to be checked</param>
    /// <returns>True if number has value of CK_UNAVAILABLE_INFORMATION constant false otherwise</returns>
    public static bool IsCkInformationUnavailable(ulong value) => value == CK_UNAVAILABLE_INFORMATION;

    /// <summary>
    /// Specifies no practical limit
    /// </summary>
    public const ulong CK_EFFECTIVELY_INFINITE = 0;

    #endregion

    #region Certificate categories (CKA_CERTIFICATE_CATEGORY)

    /// <summary>
    /// No certificate category specified
    /// </summary>
    public const ulong CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0;

    /// <summary>
    /// Certificate belongs to owner of the token
    /// </summary>
    public const ulong CK_CERTIFICATE_CATEGORY_TOKEN_USER = 1;

    /// <summary>
    /// Certificate belongs to a certificate authority
    /// </summary>
    public const ulong CK_CERTIFICATE_CATEGORY_AUTHORITY = 2;

    /// <summary>
    /// Certificate belongs to an end entity (i.e. not a CA)
    /// </summary>
    public const ulong CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3;

    #endregion

    #region JAVA MIDP security domains

    /// <summary>
    /// No JAVA MIDP security domain specified
    /// </summary>
    public const ulong CK_SECURITY_DOMAIN_UNSPECIFIED = 0;

    /// <summary>
    /// Manufacturer protection JAVA MIDP security domain
    /// </summary>
    public const ulong CK_SECURITY_DOMAIN_MANUFACTURER = 1;

    /// <summary>
    /// Operator protection JAVA MIDP security domain
    /// </summary>
    public const ulong CK_SECURITY_DOMAIN_OPERATOR = 2;

    /// <summary>
    /// Third party protection JAVA MIDP security domain
    /// </summary>
    public const ulong CK_SECURITY_DOMAIN_THIRD_PARTY = 3;

    #endregion

    #region OTP value formats (CK_OTP_FORMAT)

    /// <summary>
    /// Decimal (default) (UTF8-encoded) format of OTP value
    /// </summary>
    public const ulong CK_OTP_FORMAT_DECIMAL = 0;

    /// <summary>
    /// Hexadecimal (UTF8-encoded) format of OTP value
    /// </summary>
    public const ulong CK_OTP_FORMAT_HEXADECIMAL = 1;

    /// <summary>
    /// Alphanumeric (UTF8-encoded) format of OTP value
    /// </summary>
    public const ulong CK_OTP_FORMAT_ALPHANUMERIC = 2;

    /// <summary>
    /// Binary format of OTP value
    /// </summary>
    public const ulong CK_OTP_FORMAT_BINARY = 3;

    #endregion

    #region OTP parameter requirement levels (CK_OTP_PARAM)

    /// <summary>
    /// OTP parameter, if supplied, will be ignored
    /// </summary>
    public const ulong CK_OTP_PARAM_IGNORED = 0;

    /// <summary>
    /// OTP parameter may be supplied but need not be
    /// </summary>
    public const ulong CK_OTP_PARAM_OPTIONAL = 1;

    /// <summary>
    /// OTP parameter must be supplied
    /// </summary>
    public const ulong CK_OTP_PARAM_MANDATORY = 2;

    #endregion

    #region OTP parameter types (CK_OTP_PARAM type field)

    /// <summary>
    /// An actual OTP value
    /// </summary>
    public const ulong CK_OTP_VALUE = 0;

    /// <summary>
    /// A UTF8 string containing a PIN for use when computing or verifying PIN-based OTP values
    /// </summary>
    public const ulong CK_OTP_PIN = 1;

    /// <summary>
    /// Challenge to use when computing or verifying challenge-based OTP values
    /// </summary>
    public const ulong CK_OTP_CHALLENGE = 2;

    /// <summary>
    /// UTC time value in the form YYYYMMDDhhmmss to use when computing or verifying time-based OTP values
    /// </summary>
    public const ulong CK_OTP_TIME = 3;

    /// <summary>
    /// Counter value to use when computing or verifying counter-based OTP values
    /// </summary>
    public const ulong CK_OTP_COUNTER = 4;

    /// <summary>
    /// Bit flags indicating the characteristics of the sought OTP as defined below
    /// </summary>
    public const ulong CK_OTP_FLAGS = 5;

    /// <summary>
    /// Desired output length (overrides any default value)
    /// </summary>
    public const ulong CK_OTP_OUTPUT_LENGTH = 6;

    /// <summary>
    /// Returned OTP format
    /// </summary>
    public const ulong CK_OTP_OUTPUT_FORMAT = 7;

    #endregion
}
