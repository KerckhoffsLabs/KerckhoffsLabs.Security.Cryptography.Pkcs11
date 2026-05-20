using System.Runtime.InteropServices;

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
    public static readonly NativeCULong CK_INVALID_HANDLE = new(0);

    /// <summary>
    /// Token and/or library is unable or unwilling to provide information
    /// </summary>
    public static readonly NativeCULong CK_UNAVAILABLE_INFORMATION = new(OperatingSystem.IsWindows() ? uint.MaxValue : nuint.MaxValue);

    /// <summary>
    /// Checks whether provided number has value of CK_UNAVAILABLE_INFORMATION constant
    /// </summary>
    /// <param name="value">Number to be checked</param>
    /// <returns>True if number has value of CK_UNAVAILABLE_INFORMATION constant false otherwise</returns>
    public static bool IsCkInformationUnavailable(NativeCULong value)
    {
        return value.Equals(CK_UNAVAILABLE_INFORMATION);
    }

    /// <summary>
    /// Specifies no practical limit
    /// </summary>
    public static readonly NativeCULong CK_EFFECTIVELY_INFINITE = new(0);

    #endregion

    #region Certificate categories (CKA_CERTIFICATE_CATEGORY)

    /// <summary>
    /// No certificate category specified
    /// </summary>
    public static readonly NativeCULong CK_CERTIFICATE_CATEGORY_UNSPECIFIED = new(0);

    /// <summary>
    /// Certificate belongs to owner of the token
    /// </summary>
    public static readonly NativeCULong CK_CERTIFICATE_CATEGORY_TOKEN_USER = new(1);

    /// <summary>
    /// Certificate belongs to a certificate authority
    /// </summary>
    public static readonly NativeCULong CK_CERTIFICATE_CATEGORY_AUTHORITY = new(2);

    /// <summary>
    /// Certificate belongs to an end entity (i.e. not a CA)
    /// </summary>
    public static readonly NativeCULong CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = new(3);

    #endregion

    #region JAVA MIDP security domains

    /// <summary>
    /// No JAVA MIDP security domain specified
    /// </summary>
    public static readonly NativeCULong CK_SECURITY_DOMAIN_UNSPECIFIED = new(0);

    /// <summary>
    /// Manufacturer protection JAVA MIDP security domain
    /// </summary>
    public static readonly NativeCULong CK_SECURITY_DOMAIN_MANUFACTURER = new(1);

    /// <summary>
    /// Operator protection JAVA MIDP security domain
    /// </summary>
    public static readonly NativeCULong CK_SECURITY_DOMAIN_OPERATOR = new(2);

    /// <summary>
    /// Third party protection JAVA MIDP security domain
    /// </summary>
    public static readonly NativeCULong CK_SECURITY_DOMAIN_THIRD_PARTY = new(3);

    #endregion

    #region OTP value formats (CK_OTP_FORMAT)

    /// <summary>
    /// Decimal (default) (UTF8-encoded) format of OTP value
    /// </summary>
    public static readonly NativeCULong CK_OTP_FORMAT_DECIMAL = new(0);

    /// <summary>
    /// Hexadecimal (UTF8-encoded) format of OTP value
    /// </summary>
    public static readonly NativeCULong CK_OTP_FORMAT_HEXADECIMAL = new(1);

    /// <summary>
    /// Alphanumeric (UTF8-encoded) format of OTP value
    /// </summary>
    public static readonly NativeCULong CK_OTP_FORMAT_ALPHANUMERIC = new(2);

    /// <summary>
    /// Binary format of OTP value
    /// </summary>
    public static readonly NativeCULong CK_OTP_FORMAT_BINARY = new(3);

    #endregion

    #region OTP parameter requirement levels (CK_OTP_PARAM)

    /// <summary>
    /// OTP parameter, if supplied, will be ignored
    /// </summary>
    public static readonly NativeCULong CK_OTP_PARAM_IGNORED = new(0);

    /// <summary>
    /// OTP parameter may be supplied but need not be
    /// </summary>
    public static readonly NativeCULong CK_OTP_PARAM_OPTIONAL = new(1);

    /// <summary>
    /// OTP parameter must be supplied
    /// </summary>
    public static readonly NativeCULong CK_OTP_PARAM_MANDATORY = new(2);

    #endregion

    #region OTP parameter types (CK_OTP_PARAM type field)

    /// <summary>
    /// An actual OTP value
    /// </summary>
    public static readonly NativeCULong CK_OTP_VALUE = new(0);

    /// <summary>
    /// A UTF8 string containing a PIN for use when computing or verifying PIN-based OTP values
    /// </summary>
    public static readonly NativeCULong CK_OTP_PIN = new(1);

    /// <summary>
    /// Challenge to use when computing or verifying challenge-based OTP values
    /// </summary>
    public static readonly NativeCULong CK_OTP_CHALLENGE = new(2);

    /// <summary>
    /// UTC time value in the form YYYYMMDDhhmmss to use when computing or verifying time-based OTP values
    /// </summary>
    public static readonly NativeCULong CK_OTP_TIME = new(3);

    /// <summary>
    /// Counter value to use when computing or verifying counter-based OTP values
    /// </summary>
    public static readonly NativeCULong CK_OTP_COUNTER = new(4);

    /// <summary>
    /// Bit flags indicating the characteristics of the sought OTP as defined below
    /// </summary>
    public static readonly NativeCULong CK_OTP_FLAGS = new(5);

    /// <summary>
    /// Desired output length (overrides any default value)
    /// </summary>
    public static readonly NativeCULong CK_OTP_OUTPUT_LENGTH = new(6);

    /// <summary>
    /// Returned OTP format
    /// </summary>
    public static readonly NativeCULong CK_OTP_OUTPUT_FORMAT = new(7);

    #endregion
}
