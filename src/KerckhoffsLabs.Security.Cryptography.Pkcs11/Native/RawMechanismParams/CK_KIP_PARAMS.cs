using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to CKM_KIP_DERIVE, CKM_KIP_WRAP and CKM_KIP_MAC mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_KIP_PARAMS
{
    /// <summary>
    /// Pointer to the underlying cryptographic mechanism (CKM)
    /// </summary>
    public IntPtr Mechanism;

    /// <summary>
    /// Handle to a key that will contribute to the entropy of the derived key (CKM_KIP_DERIVE) or will be used in the MAC operation (CKM_KIP_MAC)
    /// </summary>
    public NativeCULong Key;

    /// <summary>
    /// Pointer to an input seed
    /// </summary>
    public IntPtr Seed;

    /// <summary>
    /// Length in bytes of the input seed
    /// </summary>
    public NativeCULong SeedLen;
}