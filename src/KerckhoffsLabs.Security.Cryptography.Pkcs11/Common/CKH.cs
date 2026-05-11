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
    /// <summary>
    /// Converts CKH to NativeCULong
    /// </summary>
    /// <param name="value">CKH that should be converted</param>
    /// <returns>NativeCULong with value from CKH</returns>
    public static NativeCULong ToCULong(CKH value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKH
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKH with NativeCULong value</returns>
    public static CKH ToCKH(NativeCULong value)
    {
        return (CKH)value.Value;
    }
}