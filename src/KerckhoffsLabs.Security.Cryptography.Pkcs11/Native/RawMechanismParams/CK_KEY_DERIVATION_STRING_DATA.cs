using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Provides the parameters for the CKM_CONCATENATE_BASE_AND_DATA, CKM_CONCATENATE_DATA_AND_BASE and CKM_XOR_BASE_AND_DATA mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_KEY_DERIVATION_STRING_DATA
{
    /// <summary>
    /// Pointer to the byte string
    /// </summary>
    public IntPtr Data;

    /// <summary>
    /// Length of the byte string
    /// </summary>
    public NativeCULong Len;
}