using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SSL3_MASTER_KEY_DERIVE and CKM_SSL3_MASTER_KEY_DERIVE_DH mechanisms
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS
{
    /// <summary>
    /// Client's and server's random data information
    /// </summary>
    public CK_SSL3_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Pointer to a CK_VERSION structure which receives the SSL protocol version information
    /// </summary>
    public IntPtr Version;
}