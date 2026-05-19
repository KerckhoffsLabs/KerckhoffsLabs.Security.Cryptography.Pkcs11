using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_IKE_PRF_DERIVE mechanism (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_IKE_PRF_DERIVE_PARAMS
{
    /// <summary>
    /// PRF mechanism (typically a CKM_*_HMAC variant).
    /// </summary>
    public NativeCULong PrfMechanism;

    /// <summary>
    /// True to treat the input data as the key material.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool DataAsKey;

    /// <summary>
    /// True to perform a rekey-style derivation.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool Rekey;

    /// <summary>
    /// Pointer to the initiator nonce (Ni).
    /// </summary>
    public IntPtr Ni;

    /// <summary>
    /// Length of Ni in bytes.
    /// </summary>
    public NativeCULong NiLen;

    /// <summary>
    /// Pointer to the responder nonce (Nr).
    /// </summary>
    public IntPtr Nr;

    /// <summary>
    /// Length of Nr in bytes.
    /// </summary>
    public NativeCULong NrLen;

    /// <summary>
    /// Handle of the new key (used in some rekey flows).
    /// </summary>
    public NativeCULong NewKey;
}
