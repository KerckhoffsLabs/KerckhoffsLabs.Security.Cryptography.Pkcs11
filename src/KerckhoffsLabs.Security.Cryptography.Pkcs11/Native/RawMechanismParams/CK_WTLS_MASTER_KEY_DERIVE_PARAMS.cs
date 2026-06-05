using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure, which provides the parameters to the CKM_WTLS_MASTER_KEY_DERIVE mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS
{
    /// <summary>
    /// Digest mechanism to be used (CKM)
    /// </summary>
    public NativeCULong DigestMechanism;

    /// <summary>
    /// Client's and server's random data information
    /// </summary>
    public CK_WTLS_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Pointer to single byte which receives the WTLS protocol version information
    /// </summary>
    public IntPtr Version;
}
