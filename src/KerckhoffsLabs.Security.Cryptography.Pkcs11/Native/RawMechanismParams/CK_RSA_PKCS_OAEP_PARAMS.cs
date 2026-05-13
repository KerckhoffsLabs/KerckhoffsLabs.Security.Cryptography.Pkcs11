using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RSA_PKCS_OAEP mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_RSA_PKCS_OAEP_PARAMS
{
    /// <summary>
    /// Mechanism ID of the message digest algorithm used to calculate the digest of the encoding parameter (CKM)
    /// </summary>
    public NativeCULong HashAlg;

    /// <summary>
    /// Mask generation function to use on the encoded block (CKG)
    /// </summary>
    public NativeCULong Mgf;
    
    /// <summary>
    /// Source of the encoding parameter (CKZ)
    /// </summary>
    public NativeCULong Source;
    
    /// <summary>
    /// Data used as the input for the encoding parameter source
    /// </summary>
    public IntPtr SourceData;
    
    /// <summary>
    /// Length of the encoding parameter source input
    /// </summary>
    public NativeCULong SourceDataLen;
}