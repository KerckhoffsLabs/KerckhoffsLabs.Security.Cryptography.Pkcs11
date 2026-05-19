using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_CMS_SIG mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_CMS_SIG_PARAMS
{
    /// <summary>
    /// Object handle for a certificate associated with the signing key
    /// </summary>
    public NativeCULong CertificateHandle;

    /// <summary>
    /// Mechanism to use when signing a constructed CMS SignedAttributes value
    /// </summary>
    public IntPtr SigningMechanism;

    /// <summary>
    /// Mechanism to use when digesting the data
    /// </summary>
    public IntPtr DigestMechanism;

    /// <summary>
    /// NULL-terminated string indicating complete MIME Content-type of message to be signed or null if the message is a MIME object
    /// </summary>
    public IntPtr ContentType;

    /// <summary>
    /// Pointer to DER-encoded list of CMS Attributes the caller requests to be included in the signed attributes
    /// </summary>
    public IntPtr RequestedAttributes;

    /// <summary>
    /// Length in bytes of the value pointed to by RequestedAttributes
    /// </summary>
    public NativeCULong RequestedAttributesLen;

    /// <summary>
    /// Pointer to DER-encoded list of CMS Attributes (with accompanying values) required to be included in the resulting signed attributes
    /// </summary>
    public IntPtr RequiredAttributes;

    /// <summary>
    /// Length in bytes, of the value pointed to by RequiredAttributes
    /// </summary>
    public NativeCULong RequiredAttributesLen;
}