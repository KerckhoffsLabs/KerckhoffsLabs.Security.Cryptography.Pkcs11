using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_CHACHA20_POLY1305 and
/// CKM_SALSA20_POLY1305 mechanisms (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_SALSA20_CHACHA20_POLY1305_PARAMS
{
    /// <summary>Pointer to nonce data.</summary>
    public IntPtr Nonce;

    /// <summary>Length of nonce in bytes.</summary>
    public NativeCULong NonceLen;

    /// <summary>Pointer to additional authentication data.</summary>
    public IntPtr AAD;

    /// <summary>Length of additional authentication data in bytes.</summary>
    public NativeCULong AADLen;
}
