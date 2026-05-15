using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Prehash post-quantum signing parameters used with CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA
/// (PKCS#11 v3.2). Like <see cref="CK_SIGN_ADDITIONAL_CONTEXT"/> plus the hash mechanism
/// applied to the input before signing.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_HASH_SIGN_ADDITIONAL_CONTEXT
{
    /// <summary>Hedge variant.</summary>
    public NativeCULong HedgeVariant;

    /// <summary>Pointer to context-string bytes.</summary>
    public IntPtr Context;

    /// <summary>Length of context in bytes (max 255).</summary>
    public NativeCULong ContextLen;

    /// <summary>Hash mechanism applied to the data before signing (e.g. CKM_SHA256).</summary>
    public NativeCULong Hash;
}
