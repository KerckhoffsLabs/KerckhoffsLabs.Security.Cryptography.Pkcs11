namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds the raw <c>delegate* unmanaged[Cdecl]&lt;...&gt;</c> function pointers for every
/// PKCS#11 cryptoki function the library binds. Populated by direct cast from
/// <see cref="CK_FUNCTION_LIST"/> / <see cref="CK_FUNCTION_LIST_3_0"/> / <see cref="CK_FUNCTION_LIST_3_2"/>
/// entries; no <c>Marshal.GetDelegateForFunctionPointer&lt;T&gt;</c> on this path so the
/// dispatch table is fully Native AOT compatible.
/// </summary>
/// <remarks>
/// Every field but the one below is generated from the <c>[Pkcs11Function]</c> declarations on
/// <see cref="Delegates"/>, including the Pack=1 <c>_Windows</c> twins — both members of a pair are
/// cast from the SAME native function-list entry, and only the managed struct layout differs.
/// The wrapper methods on <see cref="Delegates"/> do the per-call marshalling (pinning
/// <c>byte[]</c> / <c>CK_*[]</c> / <c>NativeCULong[]</c>, taking <c>fixed</c> addresses of
/// ref-struct parameters, converting <c>bool</c>↔<c>byte</c>) so the public dispatch
/// surface stays identical to the prior delegate-based version.
/// </remarks>
internal sealed unsafe partial class FunctionPointers
{
    /// <summary>
    /// Cryptoki <c>CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS ulFlags)</c> (v3.0).
    /// Declared here rather than generated, and the wrapper carries no <c>[Pkcs11Function]</c>:
    /// the wrapper always passes <c>pVersion</c> as <c>NULL</c> and dereferences the returned
    /// <c>CK_INTERFACE_PTR_PTR</c> itself, so this signature does not follow from its parameter
    /// list — and the pointer is bootstrapped by symbol lookup, never bound from a function list.
    /// </summary>
    public delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong> C_GetInterface;
}
