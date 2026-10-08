namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Certificate types
/// </summary>
public enum CKC : ulong
{
    /// <summary>
    /// X.509 public key certificate
    /// </summary>
    CKC_X_509 = 0x00000000,

    /// <summary>
    /// X.509 attribute certificate
    /// </summary>
    CKC_X_509_ATTR_CERT = 0x00000001,

    /// <summary>
    /// WTLS public key certificate
    /// </summary>
    CKC_WTLS = 0x00000002,

    /// <summary>
    /// Permanently reserved for token vendors
    /// </summary>
    CKC_VENDOR_DEFINED = 0x80000000
}
