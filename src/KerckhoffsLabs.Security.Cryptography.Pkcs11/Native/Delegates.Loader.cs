// <auto-split-from Delegates.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

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
    /// <summary>Resolves <paramref name="name"/> and reports whether it is present.</summary>
    private static bool TryResolve(Func<string, IntPtr> resolveExport, string name, out IntPtr address)
    {
        address = resolveExport(name);
        return address != IntPtr.Zero;
    }

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
    /// </summary>
    /// <param name="resolveExport">Export resolver for the PKCS#11 library</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
        Justification = "Calling the module's C_GetFunctionList export requires an unmanaged function-pointer " +
        "invocation, which C# only permits in unsafe code. Every outcome is guarded (missing symbol, non-OK CKR, " +
        "null function-list pointer each throw), the struct read goes through the platform-dispatching " +
        "UnmanagedMemory.Read, and which native module to trust is the consumer's explicit choice. " +
        "The path is covered hermetically by DelegatesLoaderTests, including its failure arms.")]
    private unsafe void InitializeWithGetFunctionList(Func<string, IntPtr> resolveExport)
    {
        // Mirrors NativeLibrary.GetExport's contract: a missing bootstrap symbol is fatal.
        if (!TryResolve(resolveExport, GetFunctionListSymbol, out IntPtr getFunctionListPtr))
            throw new EntryPointNotFoundException(
                $"Unable to find an entry point named '{GetFunctionListSymbol}' in the PKCS#11 library.");
        var getFunctionList = (delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)getFunctionListPtr;

        IntPtr functionList = IntPtr.Zero;

        CKR returnValue = getFunctionList(&functionList).ToCKR();
        Pkcs11Exception.ThrowIfError(returnValue, GetFunctionListSymbol);
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        _fp = CryptokiTable.Read(functionList, CryptokiTable.V240SlotCount);
    }
}
