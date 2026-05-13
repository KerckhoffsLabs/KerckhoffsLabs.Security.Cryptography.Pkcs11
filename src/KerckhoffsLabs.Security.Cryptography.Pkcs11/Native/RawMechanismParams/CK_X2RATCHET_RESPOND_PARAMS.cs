using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_X2RATCHET_RESPOND mechanism — Signal Double-Ratchet responder side (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_X2RATCHET_RESPOND_PARAMS
{
    /// <summary>
    /// Pointer to the initial shared secret (typically 32 bytes from X3DH).
    /// </summary>
    public IntPtr Sk;

    /// <summary>
    /// Handle of our own prekey.
    /// </summary>
    public NativeCULong OwnPrekey;

    /// <summary>
    /// Handle of the initiator's identity key.
    /// </summary>
    public NativeCULong InitiatorIdentity;

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
