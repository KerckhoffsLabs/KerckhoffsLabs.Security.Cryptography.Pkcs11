using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Parameters for AES key wrap with GCM (PKCS#11 v3.2). Same shape as
/// <see cref="CK_GCM_MESSAGE_PARAMS"/> but used at the wrap call site.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_GCM_WRAP_PARAMS
{
    /// <summary>Pointer to IV bytes (or a buffer the library fills when ivGenerator generates).</summary>
    public IntPtr Iv;

    /// <summary>IV length in bytes.</summary>
    public NativeCULong IvLen;

    /// <summary>Bits of the IV that are fixed (when ivGenerator generates).</summary>
    public NativeCULong IvFixedBits;

    /// <summary>IV generator selector.</summary>
    public NativeCULong IvGenerator;

    /// <summary>Pointer to AAD bytes.</summary>
    public IntPtr Aad;

    /// <summary>AAD length in bytes.</summary>
    public NativeCULong AadLen;

    /// <summary>Authentication-tag length in bits.</summary>
    public NativeCULong TagBits;
}
