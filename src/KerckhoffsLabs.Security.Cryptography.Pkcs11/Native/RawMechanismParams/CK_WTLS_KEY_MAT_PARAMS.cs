using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and the CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE mechanisms
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_WTLS_KEY_MAT_PARAMS
{
    /// <summary>
    /// The digest mechanism to be used (CKM)
    /// </summary>
    public NativeCULong DigestMechanism;

    /// <summary>
    /// The length (in bits) of the MACing key agreed upon during the protocol handshake phase
    /// </summary>
    public NativeCULong MacSizeInBits;

    /// <summary>
    /// The length (in bits) of the secret key agreed upon during the handshake phase
    /// </summary>
    public NativeCULong KeySizeInBits;

    /// <summary>
    /// The length (in bits) of the IV agreed upon during the handshake phase or if no IV is required, the length should be set to 0
    /// </summary>
    public NativeCULong IVSizeInBits;

    /// <summary>
    /// The current sequence number used for records sent by the client and server respectively
    /// </summary>
    public NativeCULong SequenceNumber;

    /// <summary>
    /// Flag which indicates whether the keys have to be derived for an export version of the protocol
    /// </summary>
    [MarshalAs(UnmanagedType.U1)]
    public bool IsExport;

    /// <summary>
    /// Client's and server's random data information
    /// </summary>
    public CK_WTLS_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Points to a CK_WTLS_KEY_MAT_OUT structure which receives the handles for the keys generated and the IV
    /// </summary>
    public IntPtr ReturnedKeyMaterial;
}