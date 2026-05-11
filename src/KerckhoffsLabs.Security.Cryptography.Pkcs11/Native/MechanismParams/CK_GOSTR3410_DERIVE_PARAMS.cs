using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_GOSTR3410_DERIVE mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_GOSTR3410_DERIVE_PARAMS
{
    /// <summary>
    /// Additional key diversification algorithm (CKD)
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// Pointer to data with public key of a receiver
    /// </summary>
    public IntPtr PublicData;

    /// <summary>
    /// Length of data with public key of a receiver. Must be 64.
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to a UKM data
    /// </summary>
    public IntPtr UKM;

    /// <summary>
    /// Length of UKM data in bytes. Must be 8.
    /// </summary>
    public NativeCULong UKMLen;
}