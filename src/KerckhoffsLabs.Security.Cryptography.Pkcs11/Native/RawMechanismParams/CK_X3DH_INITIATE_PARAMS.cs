using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_X3DH_INITIALIZE mechanism — Signal X3DH initiator side (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_X3DH_INITIATE_PARAMS
{
    /// <summary>
    /// KDF algorithm tag (CK_X3DH_KDF_TYPE).
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// Handle of the peer's identity key.
    /// </summary>
    public NativeCULong PeerIdentity;

    /// <summary>
    /// Handle of the peer's signed prekey.
    /// </summary>
    public NativeCULong PeerPrekey;

    /// <summary>
    /// Pointer to the peer's prekey signature bytes.
    /// </summary>
    public IntPtr PrekeySignature;

    /// <summary>
    /// Pointer to the peer's one-time prekey value (optional).
    /// </summary>
    public IntPtr OnetimeKey;

    /// <summary>
    /// Handle of our own identity key.
    /// </summary>
    public NativeCULong OwnIdentity;

    /// <summary>
    /// Handle of our own ephemeral key.
    /// </summary>
    public NativeCULong OwnEphemeral;
}
