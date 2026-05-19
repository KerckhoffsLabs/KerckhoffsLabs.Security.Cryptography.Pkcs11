using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_TLS12_KEY_AND_MAC_DERIVE mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_TLS12_KEY_MAT_PARAMS
{
    /// <summary>
    /// The length (in bits) of the MACing keys agreed upon during the protocol handshake phase
    /// </summary>
    public NativeCULong MacSizeInBits;

    /// <summary>
    /// The length (in bits) of the secret keys agreed upon during the protocol handshake phase
    /// </summary>
    public NativeCULong KeySizeInBits;

    /// <summary>
    /// The length (in bits) of the IV agreed upon during the protocol handshake phase
    /// </summary>
    public NativeCULong IVSizeInBits;

    /// <summary>
    /// Flag which must be set to false because export cipher suites must not be used in TLS 1.1 and later
    /// </summary>
    [MarshalAs(UnmanagedType.U1)]
    public bool IsExport;

    /// <summary>
    /// Client's and server's random data information
    /// </summary>
    public CK_SSL3_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Points to a CK_SSL3_KEY_MAT_OUT structure which receives the handles for the keys generated and the IVs
    /// </summary>
    public IntPtr ReturnedKeyMaterial;

    /// <summary>
    /// Base hash used in the underlying TLS1.2 PRF operation used to derive the master key (CKM)
    /// </summary>
    public NativeCULong PrfHashMechanism;
}