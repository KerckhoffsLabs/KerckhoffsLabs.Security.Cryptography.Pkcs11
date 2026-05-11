using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Notifications
/// </summary>
public enum CKN : uint
{
    /// <summary>
    /// Cryptoki is surrendering the execution of a function executing in a session so that the application may perform other operations
    /// </summary>
    CKN_SURRENDER = 0,

    /// <summary>
    /// Cryptoki is informing the application that the OTP for a key on a connected token just changed
    /// </summary>
    CKN_OTP_CHANGED = 1
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKNExtensions
{
    /// <summary>
    /// Converts CKN to NativeCULong
    /// </summary>
    /// <param name="value">CKN that should be converted</param>
    /// <returns>NativeCULong with value from CKN</returns>
    public static NativeCULong TOCULong(CKN value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKN
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKN with NativeCULong value</returns>
    public static CKN ToCKN(NativeCULong value)
    {
        return (CKN)value.Value;
    }
}