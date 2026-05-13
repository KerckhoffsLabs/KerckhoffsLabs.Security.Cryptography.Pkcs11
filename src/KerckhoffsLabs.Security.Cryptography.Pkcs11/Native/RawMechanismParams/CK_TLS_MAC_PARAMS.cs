using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_TLS_MAC mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_TLS_MAC_PARAMS
{
    /// <summary>
    /// Hash mechanism used in the TLS12 PRF construct or CKM_TLS_PRF to use with the TLS 1.0 and 1.1 PRF construct (CKM)
    /// </summary>
    public NativeCULong PrfHashMechanism;

    /// <summary>
    /// Length of the MAC tag required or offered
    /// </summary>
    public NativeCULong MacLength;

    /// <summary>
    /// Should be set to "1" for "server finished" label or to "2" for "client finished" label
    /// </summary>
    public NativeCULong ServerOrClient;
}