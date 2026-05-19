using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RC2_MAC_GENERAL mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_RC2_MAC_GENERAL_PARAMS
{
    /// <summary>
    /// The effective number of bits in the RC2 search space
    /// </summary>
    public NativeCULong EffectiveBits;

    /// <summary>
    /// Length of the MAC produced, in bytes
    /// </summary>
    public NativeCULong MacLength;
}