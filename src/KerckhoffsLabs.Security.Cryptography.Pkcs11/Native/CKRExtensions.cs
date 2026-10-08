using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKRExtensions
{
    /// <summary>Converts <see cref="CKR"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKR value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKR"/>. Deliberately a non-validating
    /// cast, unlike most <c>ToCK*</c> converters: return values come from the module, not the
    /// caller, and PKCS#11 permits vendor-defined codes (≥ <see cref="CKR.CKR_VENDOR_DEFINED"/>)
    /// as well as codes newer than this enum. Such values must flow into the typed
    /// <see cref="Pkcs11Exception"/> hierarchy (where they surface via
    /// <see cref="Pkcs11Exception.ReturnValue"/>), not crash the conversion.
    /// </summary>
    public static CKR ToCKR(this NativeCULong value) => (CKR)(ulong)value;
}
