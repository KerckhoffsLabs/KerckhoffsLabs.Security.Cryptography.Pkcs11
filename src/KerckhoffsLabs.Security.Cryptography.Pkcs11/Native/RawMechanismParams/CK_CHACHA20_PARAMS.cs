using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_CHACHA20 raw mechanism (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_CHACHA20_PARAMS
{
    /// <summary>
    /// Pointer to the block counter (typically 4 bytes little-endian, initial value 0 or 1 per protocol).
    /// </summary>
    public IntPtr BlockCounter;

    /// <summary>
    /// Width of the block counter in bits (32 or 64).
    /// </summary>
    public NativeCULong BlockCounterBits;

    /// <summary>
    /// Pointer to the nonce.
    /// </summary>
    public IntPtr Nonce;

    /// <summary>
    /// Length of the nonce in bits (typically 96 for IETF / 64 for legacy).
    /// </summary>
    public NativeCULong NonceBits;
}
