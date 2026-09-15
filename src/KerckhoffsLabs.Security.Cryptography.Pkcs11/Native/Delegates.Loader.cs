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

    /// <summary>Binds the v3.0 additions carried by a <see cref="CK_FUNCTION_LIST_3_0"/> table.</summary>
    private void BindV30FunctionList(CK_FUNCTION_LIST_3_0 v30)
    {
        BindLoginUser(v30.C_LoginUser);
        BindSessionCancel(v30.C_SessionCancel);
        // v3.0 func; present at the same offset in the v3.2 table, so this also covers v3.2 tokens.
        BindGetInterfaceList(v30.C_GetInterfaceList);

        BindMessageEncryptInit(v30.C_MessageEncryptInit);
        BindEncryptMessage(v30.C_EncryptMessage);
        BindEncryptMessageBegin(v30.C_EncryptMessageBegin);
        BindEncryptMessageNext(v30.C_EncryptMessageNext);
        BindMessageEncryptFinal(v30.C_MessageEncryptFinal);

        BindMessageDecryptInit(v30.C_MessageDecryptInit);
        BindDecryptMessage(v30.C_DecryptMessage);
        BindDecryptMessageBegin(v30.C_DecryptMessageBegin);
        BindDecryptMessageNext(v30.C_DecryptMessageNext);
        BindMessageDecryptFinal(v30.C_MessageDecryptFinal);

        BindMessageSignInit(v30.C_MessageSignInit);
        BindSignMessage(v30.C_SignMessage);
        BindSignMessageBegin(v30.C_SignMessageBegin);
        BindSignMessageNext(v30.C_SignMessageNext);
        BindMessageSignFinal(v30.C_MessageSignFinal);

        BindMessageVerifyInit(v30.C_MessageVerifyInit);
        BindVerifyMessage(v30.C_VerifyMessage);
        BindVerifyMessageBegin(v30.C_VerifyMessageBegin);
        BindVerifyMessageNext(v30.C_VerifyMessageNext);
        BindMessageVerifyFinal(v30.C_MessageVerifyFinal);
    }

    /// <summary>Binds the 12 v3.2 additions carried by a <see cref="CK_FUNCTION_LIST_3_2"/> table.</summary>
    private void BindV32FunctionList(CK_FUNCTION_LIST_3_2 v32)
    {
        BindEncapsulateKey(v32.C_EncapsulateKey);
        BindDecapsulateKey(v32.C_DecapsulateKey);
        BindVerifySignatureInit(v32.C_VerifySignatureInit);
        BindVerifySignature(v32.C_VerifySignature);
        BindVerifySignatureUpdate(v32.C_VerifySignatureUpdate);
        BindVerifySignatureFinal(v32.C_VerifySignatureFinal);
        BindGetSessionValidationFlags(v32.C_GetSessionValidationFlags);
        BindAsyncComplete(v32.C_AsyncComplete);
        BindAsyncGetID(v32.C_AsyncGetID);
        BindAsyncJoin(v32.C_AsyncJoin);
        BindWrapKeyAuthenticated(v32.C_WrapKeyAuthenticated);
        BindUnwrapKeyAuthenticated(v32.C_UnwrapKeyAuthenticated);
    }

    // Per-function binders for the v3.0 / v3.2 additions. Each takes a raw entry-point
    // address — IntPtr.Zero means "the token doesn't provide this function", and binding
    // is then skipped so the pointer stays null and the wrapper reports
    // CKR_FUNCTION_NOT_SUPPORTED. Both loader paths funnel through these, so the
    // signature of a function is spelled out exactly once instead of once per path,
    // and the interface-table and per-symbol routes cannot drift apart. Functions whose
    // parameters embed a NativeCULong-sensitive struct bind the Linux and Windows
    // variants from the same address; the call site picks the layout at dispatch time.

    private unsafe void BindLoginUser(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_LoginUser = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindSessionCancel(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindGetInterfaceList(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_GetInterfaceList = (delegate* unmanaged[Cdecl]<CK_INTERFACE*, NativeCULong*, NativeCULong>)address;
        _fp.C_GetInterfaceList_Windows = (delegate* unmanaged[Cdecl]<CK_INTERFACE_Windows*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindMessageEncryptInit(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_MessageEncryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)address;
        _fp.C_MessageEncryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindEncryptMessage(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_EncryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindEncryptMessageBegin(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_EncryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindEncryptMessageNext(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_EncryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageEncryptFinal(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_MessageEncryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageDecryptInit(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_MessageDecryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)address;
        _fp.C_MessageDecryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindDecryptMessage(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_DecryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindDecryptMessageBegin(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_DecryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindDecryptMessageNext(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_DecryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageDecryptFinal(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_MessageDecryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageSignInit(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_MessageSignInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)address;
        _fp.C_MessageSignInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindSignMessage(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_SignMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindSignMessageBegin(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_SignMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindSignMessageNext(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_SignMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindMessageSignFinal(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_MessageSignFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageVerifyInit(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_MessageVerifyInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)address;
        _fp.C_MessageVerifyInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifyMessage(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifyMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifyMessageBegin(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifyMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifyMessageNext(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifyMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindMessageVerifyFinal(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_MessageVerifyFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindEncapsulateKey(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_EncapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)address;
        _fp.C_EncapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindDecapsulateKey(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_DecapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)address;
        _fp.C_DecapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindVerifySignatureInit(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_VerifySignatureInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
        _fp.C_VerifySignatureInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifySignature(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifySignature = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifySignatureUpdate(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifySignatureUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindVerifySignatureFinal(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_VerifySignatureFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindGetSessionValidationFlags(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_GetSessionValidationFlags = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindAsyncComplete(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_AsyncComplete = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA*, NativeCULong>)address;
        _fp.C_AsyncComplete_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA_Windows*, NativeCULong>)address;
    }

    private unsafe void BindAsyncGetID(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_AsyncGetID = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindAsyncJoin(IntPtr address)
    {
        if (address != IntPtr.Zero)
            _fp.C_AsyncJoin = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)address;
    }

    private unsafe void BindWrapKeyAuthenticated(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_WrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
        _fp.C_WrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)address;
    }

    private unsafe void BindUnwrapKeyAuthenticated(IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;
        _fp.C_UnwrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)address;
        _fp.C_UnwrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)address;
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

        CK_FUNCTION_LIST funcList = UnmanagedMemory.Read<CK_FUNCTION_LIST>(functionList);
        Initialize(funcList);
    }
}
