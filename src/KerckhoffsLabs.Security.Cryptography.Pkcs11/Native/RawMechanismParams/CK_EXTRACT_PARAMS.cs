using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Provides the parameter to the CKM_EXTRACT_KEY_FROM_KEY mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_EXTRACT_PARAMS
{
    /// <summary>
    /// Specifies which bit of the base key should be used as the first bit of the derived key
    /// </summary>
    public NativeCULong Bit;
}