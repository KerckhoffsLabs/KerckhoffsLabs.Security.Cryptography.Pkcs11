using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Per-message ChaCha20-Poly1305 / Salsa20-Poly1305 parameter struct used with
/// CKM_CHACHA20_POLY1305 and CKM_SALSA20_POLY1305 in the v3.0 message-based AEAD API.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
{
    /// <summary>Pointer to the nonce.</summary>
    public IntPtr Nonce;

    /// <summary>Length of the nonce in bytes (12 for ChaCha20 IETF mode).</summary>
    public NativeCULong NonceLen;

    /// <summary>Pointer to the Poly1305 tag buffer (output on encrypt, input on decrypt).</summary>
    public IntPtr Tag;
}
