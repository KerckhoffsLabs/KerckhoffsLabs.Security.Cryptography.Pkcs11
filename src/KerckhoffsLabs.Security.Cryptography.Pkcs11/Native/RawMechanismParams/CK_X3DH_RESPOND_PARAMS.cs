using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_X3DH_RESPOND mechanism — Signal X3DH responder side (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_X3DH_RESPOND_PARAMS
{
    /// <summary>
    /// KDF algorithm tag (CK_X3DH_KDF_TYPE).
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// Pointer to the identity-key identifier bytes.
    /// </summary>
    public IntPtr IdentityId;

    /// <summary>
    /// Pointer to the prekey identifier bytes.
    /// </summary>
    public IntPtr PrekeyId;

    /// <summary>
    /// Pointer to the one-time prekey identifier bytes.
    /// </summary>
    public IntPtr OnetimeId;

    /// <summary>
    /// Handle of the initiator's identity key.
    /// </summary>
    public NativeCULong InitiatorIdentity;

    /// <summary>
    /// Pointer to the initiator's ephemeral public-key bytes.
    /// </summary>
    public IntPtr InitiatorEphemeral;
}
