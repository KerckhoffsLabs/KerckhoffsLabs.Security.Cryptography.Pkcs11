using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Certificate types
/// </summary>
public enum CKC : uint
{
    /// <summary>
    /// X.509 public key certificate
    /// </summary>
    CKC_X_509 = 0x00000000,

    /// <summary>
    /// X.509 attribute certificate
    /// </summary>
    CKC_X_509_ATTR_CERT = 0x00000001,

    /// <summary>
    /// WTLS public key certificate
    /// </summary>
    CKC_WTLS = 0x00000002,

    /// <summary>
    /// Permanently reserved for token vendors
    /// </summary>
    CKC_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKCExtensions
{
    /// <summary>
    /// Converts CKC to NativeCULong
    /// </summary>
    /// <param name="value">CKC that should be converted</param>
    /// <returns>NativeCULong with value from CKC</returns>
    public static NativeCULong ToCULong(this CKC value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Converts NativeCULong to CKC
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKC with NativeCULong value</returns>
    public static CKC ToCKC(this NativeCULong value)
    {
        return (CKC)value.Value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKC"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// Use this for values coming from the PKCS#11 module (return codes, attribute values, etc.)
    /// where a malformed response must fail loudly. For values that originate in trusted
    /// application code, prefer the loose <see cref="ToCKC(NativeCULong)"/> for speed.
    /// </summary>
    /// <param name="value">NativeCULong value to convert.</param>
    /// <returns>The corresponding CKC enum member.</returns>
    /// <exception cref="InvalidEnumValueException">if <paramref name="value"/> is not a defined CKC member.</exception>
    public static CKC ToCKCChecked(this NativeCULong value)
    {
        CKC result = (CKC)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKC), (ulong)value);
        return result;
    }
}