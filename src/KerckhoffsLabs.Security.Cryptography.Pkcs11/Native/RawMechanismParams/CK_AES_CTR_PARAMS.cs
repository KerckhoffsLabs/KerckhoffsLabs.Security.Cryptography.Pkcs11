using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_AES_CTR mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_AES_CTR_PARAMS
{
    /// <summary>
    /// The number of bits in the counter block (cb) that shall be incremented
    /// </summary>
    public NativeCULong CounterBits;

    /// <summary>
    /// Specifies the counter block
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Cb;
}