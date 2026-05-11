using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_AES_GCM mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_GCM_PARAMS
{
    /// <summary>
    /// Pointer to initialization vector
    /// </summary>
    public IntPtr Iv;

    /// <summary>
    /// Length of initialization vector in bytes
    /// </summary>
    public NativeCULong IvLen;

    /// <summary>
    /// Member is defined in PKCS#11 v2.40e1 headers but the description is not present in the specification
    /// </summary>
    public NativeCULong IvBits; // TODO - Fix description when fixed in PKCS#11 specification

    /// <summary>
    /// Pointer to additional authentication data
    /// </summary>
    public IntPtr AAD;

    /// <summary>
    /// Length of additional authentication data in bytes
    /// </summary>
    public NativeCULong AADLen;

    /// <summary>
    /// Length of authentication tag (output following cipher text) in bits
    /// </summary>
    public NativeCULong TagBits;
}