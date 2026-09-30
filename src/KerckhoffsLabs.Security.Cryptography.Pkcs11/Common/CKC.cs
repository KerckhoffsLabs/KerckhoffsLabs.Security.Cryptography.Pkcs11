using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Certificate types
/// </summary>
public enum CKC : ulong
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
internal static class CKCExtensions
{
    /// <summary>
    /// Converts CKC to NativeCULong
    /// </summary>
    /// <param name="value">CKC that should be converted</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    /// <returns>NativeCULong with value from CKC</returns>
    public static NativeCULong ToCULong(this CKC value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);
}
