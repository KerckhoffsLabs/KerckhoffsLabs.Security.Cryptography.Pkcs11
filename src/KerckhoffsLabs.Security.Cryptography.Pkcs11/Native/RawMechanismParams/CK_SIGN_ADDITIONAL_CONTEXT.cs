using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Generic post-quantum signing parameters used with CKM_ML_DSA and CKM_SLH_DSA
/// (PKCS#11 v3.2). Carries the hedged-vs-deterministic mode plus an optional context
/// string per FIPS 204 / 205.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_SIGN_ADDITIONAL_CONTEXT
{
    /// <summary>Hedge variant: CKH_HEDGE_PREFERRED (default), CKH_HEDGE_REQUIRED, or CKH_DETERMINISTIC_REQUIRED.</summary>
    public NativeCULong HedgeVariant;

    /// <summary>Pointer to context-string bytes (FIPS 204 §5.2.1 / FIPS 205 §10.2.1). Empty / zero for default context.</summary>
    public IntPtr Context;

    /// <summary>Length of context in bytes. Max 255 per FIPS 204/205.</summary>
    public NativeCULong ContextLen;
}
