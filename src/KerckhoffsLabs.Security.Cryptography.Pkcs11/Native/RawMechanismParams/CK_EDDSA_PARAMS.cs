using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_EDDSA mechanism (PKCS#11 v3.1). Used for Ed25519ph/Ed448ph prehash modes and contextualized variants.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_EDDSA_PARAMS
{
    /// <summary>
    /// True selects the prehash variant (Ed25519ph / Ed448ph). False selects pure Ed25519 / Ed448.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool PhFlag;

    /// <summary>
    /// Length of the context-data buffer in bytes.
    /// </summary>
    public NativeCULong ContextDataLen;

    /// <summary>
    /// Pointer to the context-data buffer (empty for vanilla Ed25519/Ed448).
    /// </summary>
    public IntPtr ContextData;
}
