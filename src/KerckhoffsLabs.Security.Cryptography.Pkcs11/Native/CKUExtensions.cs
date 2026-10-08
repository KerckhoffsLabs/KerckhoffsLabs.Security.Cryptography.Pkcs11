using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKUExtensions
{
    /// <summary>Converts <see cref="CKU"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKU value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);
}
