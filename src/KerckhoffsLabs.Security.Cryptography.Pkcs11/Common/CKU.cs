using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Types of Cryptoki users
/// </summary>
public enum CKU : uint
{
    /// <summary>
    /// Security Officer
    /// </summary>
    CKU_SO = 0,

    /// <summary>
    /// Normal user
    /// </summary>
    CKU_USER = 1,

    /// <summary>
    /// Context specific
    /// </summary>
    CKU_CONTEXT_SPECIFIC = 2
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKUExtensions
{
    /// <summary>
    /// Converts CKU to NativeCULong
    /// </summary>
    /// <param name="value">CKU that should be converted</param>
    /// <returns>NativeCULong with value from CKU</returns>
    public static NativeCULong ToCULong(CKU value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKU
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKU with NativeCULong value</returns>
    public static CKU ToCKU(NativeCULong value)
    {
        return (CKU)value.Value;
    }
}