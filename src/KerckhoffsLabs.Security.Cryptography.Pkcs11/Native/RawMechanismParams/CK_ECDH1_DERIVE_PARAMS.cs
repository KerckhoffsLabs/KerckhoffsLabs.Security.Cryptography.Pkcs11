using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters for the CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE key derivation mechanisms
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_ECDH1_DERIVE_PARAMS
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
    /// The length in bytes of the other party's EC public key
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to other party's EC public key value
    /// </summary>
    public IntPtr PublicData;
}
