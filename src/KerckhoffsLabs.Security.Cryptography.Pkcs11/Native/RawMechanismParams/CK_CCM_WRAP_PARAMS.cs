using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Parameters for AES key wrap with CCM (PKCS#11 v3.2).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_CCM_WRAP_PARAMS
{
    /// <summary>Length of the wrapped-key data in bytes (required up front for CCM).</summary>
    public NativeCULong DataLen;

    /// <summary>Pointer to nonce bytes.</summary>
    public IntPtr Nonce;

    /// <summary>Nonce length in bytes.</summary>
    public NativeCULong NonceLen;

    /// <summary>Bits of the nonce that are fixed (when nonceGenerator generates).</summary>
    public NativeCULong NonceFixedBits;

    /// <summary>Nonce generator selector.</summary>
    public NativeCULong NonceGenerator;

    /// <summary>Pointer to AAD bytes.</summary>
    public IntPtr Aad;

    /// <summary>AAD length in bytes.</summary>
    public NativeCULong AadLen;

    /// <summary>MAC length in bytes.</summary>
    public NativeCULong MacLen;
}
