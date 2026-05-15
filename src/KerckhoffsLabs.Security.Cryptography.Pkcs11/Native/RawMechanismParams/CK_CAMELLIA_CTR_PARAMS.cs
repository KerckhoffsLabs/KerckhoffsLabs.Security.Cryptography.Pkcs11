using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_CAMELLIA_CTR mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_CAMELLIA_CTR_PARAMS
{
    /// <summary>
    /// Specifies the number of bits in the counter block (cb) that shall be incremented
    /// </summary>
    public NativeCULong CounterBits;

    /// <summary>
    /// Specifies the counter block
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Cb;
}