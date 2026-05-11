using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_DES_CBC_ENCRYPT_DATA and CKM_DES3_CBC_ENCRYPT_DATA mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_DES_CBC_ENCRYPT_DATA_PARAMS
{
    /// <summary>
    /// IV value
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Iv;

    /// <summary>
    /// Data value part that must be a multiple of 8 bytes long
    /// </summary>
    public IntPtr Data;

    /// <summary>
    /// Length of data in bytes
    /// </summary>
    public NativeCULong Length;
}