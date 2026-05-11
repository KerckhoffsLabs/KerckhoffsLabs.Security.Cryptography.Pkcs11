using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RC2_CBC and CKM_RC2_CBC_PAD mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_RC2_CBC_PARAMS
{
    /// <summary>
    /// The effective number of bits in the RC2 search space
    /// </summary>
    public NativeCULong EffectiveBits;

    /// <summary>
    /// The initialization vector (IV) for cipher block chaining mode
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Iv;
}