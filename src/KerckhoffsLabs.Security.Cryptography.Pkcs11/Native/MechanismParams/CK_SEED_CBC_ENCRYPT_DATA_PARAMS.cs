using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SEED_CBC_ENCRYPT_DATA mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_SEED_CBC_ENCRYPT_DATA_PARAMS
{
    /// <summary>
    /// IV value
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Iv;

    /// <summary>
    /// Data value part that must be a multiple of 16 bytes long
    /// </summary>
    public IntPtr Data;

    /// <summary>
    /// Length of data in bytes
    /// </summary>
    public NativeCULong Length;
}