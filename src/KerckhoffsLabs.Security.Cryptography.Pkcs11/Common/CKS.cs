using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Session States
/// </summary>
public enum CKS : uint
{
    /// <summary>
    /// The application has opened a read-only session. The application has read-only access to public token objects and read/write access to public session objects.
    /// </summary>
    CKS_RO_PUBLIC_SESSION = 0,
    
    /// <summary>
    /// The normal user has been authenticated to the token. The application has read-only access to all token objects (public or private) and read/write access to all session objects (public or private).
    /// </summary>
    CKS_RO_USER_FUNCTIONS = 1,
    
    /// <summary>
    /// The application has opened a read/write session. The application has read/write access to all public objects.
    /// </summary>
    CKS_RW_PUBLIC_SESSION = 2,
    
    /// <summary>
    /// The normal user has been authenticated to the token. The application has read/write access to all objects.
    /// </summary>
    CKS_RW_USER_FUNCTIONS = 3,
    
    /// <summary>
    /// The Security Officer has been authenticated to the token. The application has read/write access only to public objects on the token, not to private objects. The SO can set the normal user's PIN.
    /// </summary>
    CKS_RW_SO_FUNCTIONS = 4
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKSExtensions
{
    /// <summary>
    /// Converts CKS to NativeCULong
    /// </summary>
    /// <param name="value">CKS that should be converted</param>
    /// <returns>NativeCULong with value from CKS</returns>
    public static NativeCULong ToCULong(CKS value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKS
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKS with NativeCULong value</returns>
    public static CKS ToCKS(NativeCULong value)
    {
        return (CKS)value.Value;
    }
}