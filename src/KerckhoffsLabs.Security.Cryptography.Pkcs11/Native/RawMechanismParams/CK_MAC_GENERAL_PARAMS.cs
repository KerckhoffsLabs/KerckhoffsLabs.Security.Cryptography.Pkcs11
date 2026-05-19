using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the general-length MACing mechanisms (DES, DES3, CAST, CAST3, CAST128 (CAST5), IDEA, CDMF and AES), the general length HMACing mechanisms (MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512, RIPEMD-128 and RIPEMD-160) and the two SSL 3.0 MACing mechanisms (MD5 and SHA-1)
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_MAC_GENERAL_PARAMS
{
    /// <summary>
    /// Length of the MAC produced, in bytes
    /// </summary>
    public NativeCULong MacLength;
}