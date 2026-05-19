using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_ECDH_AES_KEY_WRAP mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_ECDH_AES_KEY_WRAP_PARAMS
{
    /// <summary>
    /// Length of the temporary AES key in bits
    /// </summary>
    public NativeCULong AESKeyBits;

    /// <summary>
    /// Key derivation function used on the shared secret value to generate AES key (CKD)
    /// </summary>
    public NativeCULong Kdf;

    /// <summary>
    /// Length in bytes of the shared info
    /// </summary>
    public NativeCULong SharedDataLen;

    /// <summary>
    /// Data shared between the two parties
    /// </summary>
    public IntPtr SharedData;
}