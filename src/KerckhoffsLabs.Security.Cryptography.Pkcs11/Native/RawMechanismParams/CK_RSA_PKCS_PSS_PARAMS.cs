using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RSA_PKCS_PSS mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_RSA_PKCS_PSS_PARAMS
{
    /// <summary>
    /// Hash algorithm used in the PSS encoding (CKM)
    /// </summary>
    public NativeCULong HashAlg;
    
    /// <summary>
    /// Mask generation function to use on the encoded block (CKG)
    /// </summary>
    public NativeCULong Mgf;

    /// <summary>
    /// Length, in bytes, of the salt value used in the PSS encoding
    /// </summary>
    public NativeCULong Len;
}