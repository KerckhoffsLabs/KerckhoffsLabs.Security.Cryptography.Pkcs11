using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_TLS_KDF mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_TLS_KDF_PARAMS
{
    /// <summary>
    /// Hash mechanism used in the TLS 1.2 PRF construct or CKM_TLS_PRF to use with the TLS 1.0 and 1.1 PRF construct (CKM)
    /// </summary>
    public NativeCULong PrfMechanism;

    /// <summary>
    /// Pointer to the label for this key derivation
    /// </summary>
    public IntPtr Label;

    /// <summary>
    /// Length of the label in bytes
    /// </summary>
    public NativeCULong LabelLength;

    /// <summary>
    /// Random data for the key derivation
    /// </summary>
    public CK_SSL3_RANDOM_DATA RandomInfo;

    /// <summary>
    /// Pointer to the context data for this key derivation
    /// </summary>
    public IntPtr ContextData;

    /// <summary>
    /// Length of the context data in bytes
    /// </summary>
    public NativeCULong ContextDataLength;
}