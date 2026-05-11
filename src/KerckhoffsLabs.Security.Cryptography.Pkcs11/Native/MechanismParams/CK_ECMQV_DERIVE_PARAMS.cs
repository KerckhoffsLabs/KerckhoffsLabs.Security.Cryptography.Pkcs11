using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
///  Structure that provides the parameters to the CKM_ECMQV_DERIVE mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_ECMQV_DERIVE_PARAMS
{
    /// <summary>
    /// Key derivation function used on the shared secret value (CKD)
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// The length in bytes of the shared info
    /// </summary>
    public NativeCULong SharedDataLen;

    /// <summary>
    /// Some data shared between the two parties
    /// </summary>
    public IntPtr SharedData;

    /// <summary>
    /// The length in bytes of the other party's first EC public key
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to other party's first EC public key value
    /// </summary>
    public IntPtr PublicData;

    /// <summary>
    /// The length in bytes of the second EC private key
    /// </summary>
    public NativeCULong PrivateDataLen;

    /// <summary>
    /// Key handle for second EC private key value
    /// </summary>
    public NativeCULong PrivateData;

    /// <summary>
    /// The length in bytes of the other party's second EC public key
    /// </summary>
    public NativeCULong PublicDataLen2;

    /// <summary>
    /// Pointer to other party's second EC public key value
    /// </summary>
    public IntPtr PublicData2;

    /// <summary>
    /// Handle to the first party's ephemeral public key
    /// </summary>
    public NativeCULong PublicKey;
}