using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_TLS12_MASTER_KEY_DERIVE mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS
{
    /// <summary>
    /// Client's and server's random data information
    /// </summary>
    public CK_SSL3_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Pointer to a CK_VERSION structure which receives the SSL protocol version information
    /// </summary>
    public IntPtr Version;

    /// <summary>
    /// Base hash used in the underlying TLS 1.2 PRF operation used to derive the master key (CKM)
    /// </summary>
    public NativeCULong PrfHashMechanism;
}