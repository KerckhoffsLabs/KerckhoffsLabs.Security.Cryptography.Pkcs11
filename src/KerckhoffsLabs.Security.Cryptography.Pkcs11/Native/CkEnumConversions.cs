using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Conversions between the PKCS#11 constant enums and the native <c>CK_ULONG</c> width. Values going to
/// the module are checked by <see cref="CkULong.From"/>, since <c>CK_ULONG</c> is 32-bit on Windows.
/// Values coming back are cast without validation, because the module may return vendor-defined or newer
/// codes.
/// </summary>
internal static class CkEnumConversions
{
    /// <summary>Converts <see cref="CKA"/> to <see cref="NativeCULong"/>.</summary>
    /// <param name="value">The attribute type to convert.</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    public static NativeCULong ToCULong(this CKA value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>Converts <see cref="CKD"/> to <see cref="NativeCULong"/>.</summary>
    /// <param name="value">The key derivation function to convert.</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    public static NativeCULong ToCULong(this CKD value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>Converts <see cref="CKM"/> to <see cref="NativeCULong"/>.</summary>
    /// <param name="value">The mechanism type to convert.</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    public static NativeCULong ToCULong(this CKM value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>Converts <see cref="CKR"/> to <see cref="NativeCULong"/>.</summary>
    /// <param name="value">The return value to convert.</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    public static NativeCULong ToCULong(this CKR value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>Converts <see cref="CKU"/> to <see cref="NativeCULong"/>.</summary>
    /// <param name="value">The user type to convert.</param>
    /// <param name="paramName">The argument name reported if the value does not fit; supplied by the compiler.</param>
    public static NativeCULong ToCULong(this CKU value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKM"/>. Deliberately a non-validating cast:
    /// mechanism values read back from native structures may legally be vendor-defined
    /// (≥ <see cref="CKM.CKM_VENDOR_DEFINED"/>) or newer than this enum, and must round-trip rather than
    /// crash the conversion.
    /// </summary>
    public static CKM ToCKM(this NativeCULong value) => (CKM)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKR"/>. Deliberately a non-validating cast:
    /// return values come from the module, not the caller, and PKCS#11 permits vendor-defined codes
    /// (≥ <see cref="CKR.CKR_VENDOR_DEFINED"/>) as well as codes newer than this enum. Such values must
    /// flow into the typed <see cref="Pkcs11Exception"/> hierarchy (where they surface via
    /// <see cref="Pkcs11Exception.ReturnValue"/>), not crash the conversion.
    /// </summary>
    public static CKR ToCKR(this NativeCULong value) => (CKR)(ulong)value;
}
