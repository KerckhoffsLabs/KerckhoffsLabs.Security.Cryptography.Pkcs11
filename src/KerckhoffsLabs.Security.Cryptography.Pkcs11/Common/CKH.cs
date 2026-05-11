using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Hardware feature types
/// </summary>
public enum CKH : uint
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
public static class CKHExtensions
{
    /// <summary>Converts <see cref="CKH"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKH value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKH"/>. Use only when the
    /// value is trusted; otherwise prefer <see cref="ToCKHChecked"/>.
    /// </summary>
    public static CKH ToCKH(this NativeCULong value)
    {
        return (CKH)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKH"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKH ToCKHChecked(this NativeCULong value)
    {
        CKH result = (CKH)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKH), (ulong)value);
        return result;
    }
}