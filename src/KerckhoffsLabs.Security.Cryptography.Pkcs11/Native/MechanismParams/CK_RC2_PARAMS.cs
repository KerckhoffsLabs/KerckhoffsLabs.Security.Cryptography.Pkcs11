using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Provides the parameters to the CKM_RC2_ECB and CKM_RC2_MAC mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_RC2_PARAMS
{
    /// <summary>
    /// Effective number of bits in the RC2 search space
    /// </summary>
    public NativeCULong EffectiveBits;
}