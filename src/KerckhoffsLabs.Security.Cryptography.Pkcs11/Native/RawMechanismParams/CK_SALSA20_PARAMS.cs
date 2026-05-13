using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SALSA20 raw mechanism (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_SALSA20_PARAMS
{
    /// <summary>
    /// Pointer to the block counter (8 bytes).
    /// </summary>
    public IntPtr BlockCounter;

    /// <summary>
    /// Pointer to the nonce (8 bytes).
    /// </summary>
    public IntPtr Nonce;

    /// <summary>
    /// Length of the nonce in bits (typically 64).
    /// </summary>
    public NativeCULong NonceBits;
}
