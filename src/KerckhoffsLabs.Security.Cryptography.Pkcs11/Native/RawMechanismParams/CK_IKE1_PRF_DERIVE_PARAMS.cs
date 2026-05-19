using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_IKE1_PRF_DERIVE mechanism — IKEv1 PRF key derivation (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_IKE1_PRF_DERIVE_PARAMS
{
    /// <summary>
    /// PRF mechanism.
    /// </summary>
    public NativeCULong PrfMechanism;

    /// <summary>
    /// True if PrevKey is valid.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool HasPrevKey;

    /// <summary>
    /// Handle of the shared-secret key g^xy.
    /// </summary>
    public NativeCULong Keygxy;

    /// <summary>
    /// Handle of the previous-iteration key (when HasPrevKey is true).
    /// </summary>
    public NativeCULong PrevKey;

    /// <summary>
    /// Pointer to initiator cookie (CKY_I).
    /// </summary>
    public IntPtr CkyI;

    /// <summary>
    /// Length of CKY_I in bytes.
    /// </summary>
    public NativeCULong CkyILen;

    /// <summary>
    /// Pointer to responder cookie (CKY_R).
    /// </summary>
    public IntPtr CkyR;

    /// <summary>
    /// Length of CKY_R in bytes.
    /// </summary>
    public NativeCULong CkyRLen;

    /// <summary>
    /// IKEv1 derivation step index (KEYMAT_INDEX).
    /// </summary>
    public byte KeyNumber;
}
