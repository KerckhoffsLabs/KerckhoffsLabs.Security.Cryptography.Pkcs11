using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_IKE2_PRF_PLUS_DERIVE mechanism — IKEv2 PRF+ per RFC 7296 §2.13 (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_IKE2_PRF_PLUS_DERIVE_PARAMS
{
    /// <summary>
    /// PRF mechanism (typically a CKM_*_HMAC variant).
    /// </summary>
    public NativeCULong PrfMechanism;

    /// <summary>
    /// True if SeedKey is a valid key handle.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool HasSeedKey;

    /// <summary>
    /// Handle of the seed key (when HasSeedKey is true).
    /// </summary>
    public NativeCULong SeedKey;

    /// <summary>
    /// Pointer to the seed data bytes.
    /// </summary>
    public IntPtr SeedData;

    /// <summary>
    /// Length of the seed data in bytes.
    /// </summary>
    public NativeCULong SeedDataLen;
}
