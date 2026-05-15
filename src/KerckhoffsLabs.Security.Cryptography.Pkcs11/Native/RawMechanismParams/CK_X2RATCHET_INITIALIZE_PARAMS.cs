using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_X2RATCHET_INITIALIZE mechanism — Signal Double-Ratchet initiator side (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_X2RATCHET_INITIALIZE_PARAMS
{
    /// <summary>
    /// Pointer to the initial shared secret (typically 32 bytes from X3DH).
    /// </summary>
    public IntPtr Sk;

    /// <summary>
    /// Handle of the peer's public prekey.
    /// </summary>
    public NativeCULong PeerPublicPrekey;

    /// <summary>
    /// Handle of the peer's public identity key.
    /// </summary>
    public NativeCULong PeerPublicIdentity;

    /// <summary>
    /// Handle of our own public identity key.
    /// </summary>
    public NativeCULong OwnPublicIdentity;

    /// <summary>
    /// True to enable header encryption.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool EncryptedHeader;

    /// <summary>
    /// Elliptic curve identifier.
    /// </summary>
    public NativeCULong Curve;

    /// <summary>
    /// Mechanism used for AEAD encryption of messages.
    /// </summary>
    public NativeCULong AeadMechanism;

    /// <summary>
    /// KDF mechanism for the ratchet (CK_X2RATCHET_KDF_TYPE).
    /// </summary>
    public NativeCULong KdfMechanism;
}
