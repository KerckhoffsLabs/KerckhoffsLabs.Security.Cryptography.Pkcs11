using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>Conversion helpers between <see cref="CKM"/> and the native <c>CK_ULONG</c> width.</summary>
internal static class CKMExtensions
{
    /// <summary>
    /// Converts CKM to NativeCULong
    /// </summary>
    /// <param name="value">CKM that should be converted</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    /// <returns>NativeCULong with value from CKM</returns>
    public static NativeCULong ToCULong(this CKM value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKM"/>. Deliberately a non-validating
    /// cast, unlike most <c>ToCK*</c> converters: mechanism values read back from native
    /// structures may legally be vendor-defined (≥ <see cref="CKM.CKM_VENDOR_DEFINED"/>) or
    /// newer than this enum, and must round-trip rather than crash the conversion.
    /// </summary>
    public static CKM ToCKM(this NativeCULong value) => (CKM)(ulong)value;
}
