using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_XEDDSA mechanism — XEdDSA Signal-protocol signing scheme (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_XEDDSA_PARAMS
{
    /// <summary>
    /// Hash function (CK_XEDDSA_HASH_TYPE).
    /// </summary>
    public NativeCULong Hash;
}
