using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_X9_42_MQV_DERIVE key derivation mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_X9_42_MQV_DERIVE_PARAMS
{
    /// <summary>
    /// Key derivation function used on the shared secret value (CKD)
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// The length in bytes of the other info
    /// </summary>
    public NativeCULong OtherInfoLen;

    /// <summary>
    /// Some data shared between the two parties
    /// </summary>
    public IntPtr OtherInfo;

    /// <summary>
    /// The length in bytes of the other party's first X9.42 Diffie-Hellman public key
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to other party's first X9.42 Diffie-Hellman public key value
    /// </summary>
    public IntPtr PublicData;

    /// <summary>
    /// The length in bytes of the second X9.42 Diffie-Hellman private key
    /// </summary>
    public NativeCULong PrivateDataLen;

    /// <summary>
    /// Key handle for second X9.42 Diffie-Hellman private key value
    /// </summary>
    public NativeCULong PrivateData;

    /// <summary>
    /// The length in bytes of the other party's second X9.42 Diffie-Hellman public key
    /// </summary>
    public NativeCULong PublicDataLen2;

    /// <summary>
    /// Pointer to other party's second X9.42 Diffie-Hellman public key value
    /// </summary>
    public IntPtr PublicData2;

    /// <summary>
    /// Handle to the first party's ephemeral public key
    /// </summary>
    public NativeCULong PublicKey;
}