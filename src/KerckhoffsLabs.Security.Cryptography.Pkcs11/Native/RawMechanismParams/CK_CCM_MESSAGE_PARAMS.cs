using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Per-message AES-CCM parameter struct used with CKM_AES_CCM in the v3.0 message-based
/// AEAD API. Like GCM but with a plaintext-length-must-be-known-up-front constraint
/// (<see cref="DataLen"/>) and the MAC separated via <see cref="Mac"/>.
/// </summary>
[PlatformSpecificPack]
public struct CK_CCM_MESSAGE_PARAMS
{
    /// <summary>Length of the plaintext (or expected plaintext on decrypt) in bytes. Required up front in CCM.</summary>
    public NativeCULong DataLen;

    /// <summary>Pointer to the nonce.</summary>
    public IntPtr Nonce;

    /// <summary>Length of the nonce in bytes (7..13 per RFC 3610).</summary>
    public NativeCULong NonceLen;

    /// <summary>Bits of the nonce that are fixed when <see cref="NonceGenerator"/> requests generation.</summary>
    public NativeCULong NonceFixedBits;

    /// <summary>Nonce generator selector (CKG_NO_GENERATE for caller-supplied nonces).</summary>
    public NativeCULong NonceGenerator;

    /// <summary>Pointer to the MAC buffer (output on encrypt, input on decrypt).</summary>
    public IntPtr Mac;

    /// <summary>MAC length in bytes (per RFC 3610: 4, 6, 8, 10, 12, 14, or 16).</summary>
    public NativeCULong MacLen;
}
