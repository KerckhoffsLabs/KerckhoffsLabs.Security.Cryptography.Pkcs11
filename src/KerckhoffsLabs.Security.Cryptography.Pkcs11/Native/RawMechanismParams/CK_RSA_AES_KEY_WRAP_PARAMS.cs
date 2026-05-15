using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RSA_AES_KEY_WRAP mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_RSA_AES_KEY_WRAP_PARAMS
{
    /// <summary>
    /// Length of the temporary AES key in bits
    /// </summary>
    public NativeCULong AESKeyBits;

    /// <summary>
    /// Pointer to the parameters of the temporary AES key wrapping (CK_RSA_PKCS_OAEP_PARAMS)
    /// </summary>
    public IntPtr OAEPParams;
}