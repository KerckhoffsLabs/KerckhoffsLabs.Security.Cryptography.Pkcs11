// <auto-split-from Delegates.cs>

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the cryptoki dispatch boundary, and every unsafe region in it is one of " +
    "exactly three things C# permits nowhere else: invoking an unmanaged function pointer, pinning a managed " +
    "buffer for the duration of a native call, and taking the address of a blittable struct to pass as a " +
    "CK_*_PTR. There is no version of this file that satisfies the rule and still dispatches to a PKCS#11 " +
    "module. Suppressed at the type rather than per member so the rule keeps its value everywhere else: an " +
    "unsafe block appearing outside this boundary is still reported, and that is the case worth reviewing. " +
    "The safety argument does not rest on the suppression — every pointer is either pinned by a fixed " +
    "statement scoped to the call, or the address of a local, and every function pointer is null-checked by " +
    "ThrowIfUnbound before invocation. The dispatch table's binding is covered hermetically by " +
    "DelegatesLoaderTests, and the wrappers themselves by the full suite against SoftHSM2 and opencryptoki.")]
internal partial class Delegates
{
    /// <summary>Wrapper for <c>C_GetFunctionStatus</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetFunctionStatus(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_GetFunctionStatus);
        return _fp.C_GetFunctionStatus(session);
    }

    /// <summary>Wrapper for <c>C_CancelFunction</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CancelFunction(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_CancelFunction);
        return _fp.C_CancelFunction(session);
    }
}
