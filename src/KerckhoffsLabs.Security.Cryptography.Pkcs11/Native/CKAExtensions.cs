using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKAExtensions
{
    /// <summary>
    /// Converts CKA to NativeCULong
    /// </summary>
    /// <param name="value">CKA that should be converted</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    /// <returns>NativeCULong with value from CKA</returns>
    public static NativeCULong ToCULong(this CKA value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);
}
