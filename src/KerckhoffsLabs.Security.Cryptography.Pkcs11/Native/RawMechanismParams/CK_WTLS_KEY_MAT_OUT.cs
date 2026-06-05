using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that contains the resulting key handles and initialization vectors after performing a C_DeriveKey function with the CKM_WTLS_SEVER_KEY_AND_MAC_DERIVE or with the CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_WTLS_KEY_MAT_OUT
{
    /// <summary>
    /// Key handle for the resulting MAC secret key
    /// </summary>
    public NativeCULong MacSecret;

    /// <summary>
    /// Key handle for the resulting secret key
    /// </summary>
    public NativeCULong Key;

    /// <summary>
    /// Pointer to a location which receives the initialization vector (IV) created (if any)
    /// </summary>
    public IntPtr IV;
}
