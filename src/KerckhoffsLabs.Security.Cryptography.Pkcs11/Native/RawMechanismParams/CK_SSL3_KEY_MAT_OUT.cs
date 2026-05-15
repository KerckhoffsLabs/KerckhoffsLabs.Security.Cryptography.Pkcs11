using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that contains the resulting key handles and initialization vectors after performing a C_DeriveKey function with the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_SSL3_KEY_MAT_OUT
{
    /// <summary>
    /// Key handle for the resulting Client MAC Secret key
    /// </summary>
    public NativeCULong ClientMacSecret;

    /// <summary>
    /// Key handle for the resulting Server MAC Secret key
    /// </summary>
    public NativeCULong ServerMacSecret;

    /// <summary>
    /// Key handle for the resulting Client Secret key
    /// </summary>
    public NativeCULong ClientKey;

    /// <summary>
    /// Key handle for the resulting Server Secret key
    /// </summary>
    public NativeCULong ServerKey;

    /// <summary>
    /// Pointer to a location which receives the initialization vector (IV) created for the client (if any)
    /// </summary>
    public IntPtr IVClient;

    /// <summary>
    /// Pointer to a location which receives the initialization vector (IV) created for the server (if any)
    /// </summary>
    public IntPtr IVServer;
}