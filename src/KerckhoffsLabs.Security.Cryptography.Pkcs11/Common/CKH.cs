using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Hardware feature types
/// </summary>
public enum CKH : ulong
{
    /// <summary>
    /// Monotonic counter objects represent hardware counters that exist on the device.
    /// </summary>
    CKH_MONOTONIC_COUNTER = 0x00000001,

    /// <summary>
    /// Clock objects represent real-time clocks that exist on the device.
    /// </summary>
    CKH_CLOCK = 0x00000002,

    /// <summary>
    /// User interface objects represent the presentation capabilities of the device.
    /// </summary>
    CKH_USER_INTERFACE = 0x00000003,

    /// <summary>
    /// Permanently reserved for token vendors.
    /// </summary>
    CKH_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
internal static class CKHExtensions
{
    /// <summary>Converts <see cref="CKH"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKH value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        => CkULong.From((ulong)value, paramName);
}
