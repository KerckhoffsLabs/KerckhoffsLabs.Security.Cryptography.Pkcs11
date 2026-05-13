using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_CAMELLIA_CBC_ENCRYPT_DATA mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS
{
    /// <summary>
    /// 16-octet initialization vector
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Iv;

    /// <summary>
    /// Pointer to data to encrypt
    /// </summary>
    public IntPtr Data;

    /// <summary>
    /// Length of data to encrypt
    /// </summary>
    public NativeCULong Length;
}