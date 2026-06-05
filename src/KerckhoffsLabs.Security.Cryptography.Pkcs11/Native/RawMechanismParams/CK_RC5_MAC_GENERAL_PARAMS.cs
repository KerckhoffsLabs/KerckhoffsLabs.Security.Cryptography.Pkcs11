using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RC5_MAC_GENERAL mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_RC5_MAC_GENERAL_PARAMS
{
    /// <summary>
    /// Wordsize of RC5 cipher in bytes
    /// </summary>
    public NativeCULong Wordsize;

    /// <summary>
    /// Number of rounds of RC5 encipherment
    /// </summary>
    public NativeCULong Rounds;

    /// <summary>
    /// Length of the MAC produced, in bytes
    /// </summary>
    public NativeCULong MacLength;
}
