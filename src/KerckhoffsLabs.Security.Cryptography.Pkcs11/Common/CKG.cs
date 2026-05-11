using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Mask generation functions
/// </summary>
public enum CKG : uint
{
    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-1 digest algorithm
    /// </summary>
    CKG_MGF1_SHA1 = 0x00000001,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-256 digest algorithm
    /// </summary>
    CKG_MGF1_SHA256 = 0x00000002,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-384 digest algorithm
    /// </summary>
    CKG_MGF1_SHA384 = 0x00000003,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-512 digest algorithm
    /// </summary>
    CKG_MGF1_SHA512 = 0x00000004,

    /// <summary>
    /// PKCS #1 Mask Generation Function with SHA-224 digest algorithm
    /// </summary>
    CKG_MGF1_SHA224 = 0x00000005
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKGExtensions
{
    /// <summary>
    /// Converts CKG to NativeCULong
    /// </summary>
    /// <param name="value">CKG that should be converted</param>
    /// <returns>NativeCULong with value from CKG</returns>
    public static NativeCULong ToCULong(CKG value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKG
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKG with NativeCULong value</returns>
    public static CKG ToCKG(NativeCULong value)
    {
        return (CKG)value.Value;
    }
}