using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RC5_ECB and CKM_RC5_MAC mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_RC5_PARAMS
{
    /// <summary>
    /// Wordsize of RC5 cipher in bytes
    /// </summary>
    public NativeCULong Wordsize;

    /// <summary>
    /// Number of rounds of RC5 encipherment
    /// </summary>
    public NativeCULong Rounds;
}