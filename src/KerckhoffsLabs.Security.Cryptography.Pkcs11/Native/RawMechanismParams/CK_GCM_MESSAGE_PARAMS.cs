using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Per-message AES-GCM parameter struct used with CKM_AES_GCM in the v3.0 message-based
/// AEAD API (C_EncryptMessage / C_DecryptMessage). Tag bytes are read or written through
/// the <see cref="Tag"/> pointer rather than appended to the ciphertext.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_GCM_MESSAGE_PARAMS
{
    /// <summary>Pointer to the IV / nonce.</summary>
    public IntPtr Iv;

    /// <summary>Length of the IV in bytes.</summary>
    public NativeCULong IvLen;

    /// <summary>Bits of the IV that are fixed (non-random) when <see cref="IvGenerator"/> requests generation. Zero for caller-supplied IVs.</summary>
    public NativeCULong IvFixedBits;

    /// <summary>IV generator selector (CKG_NO_GENERATE for caller-supplied IVs).</summary>
    public NativeCULong IvGenerator;

    /// <summary>Pointer to the authentication tag buffer (output on encrypt, input on decrypt).</summary>
    public IntPtr Tag;

    /// <summary>Authentication-tag length in bits (multiple of 8 in [32, 128]).</summary>
    public NativeCULong TagBits;
}
