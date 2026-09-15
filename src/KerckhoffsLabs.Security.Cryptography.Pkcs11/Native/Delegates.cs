using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds delegates for all PKCS#11 functions
/// </summary>
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

    internal readonly FunctionPointers _fp = new();

    /// <summary>Native cryptoki bootstrap symbol name, used for export lookup and error context (S1192).</summary>
    private const string GetFunctionListSymbol = "C_GetFunctionList";

    /// <summary>
    /// Guards a wrapper against a function the loaded module never provided. The cryptoki name
    /// comes from the calling wrapper — each one is named after the function it dispatches to —
    /// so the error context cannot drift from the pointer being tested.
    /// </summary>
    /// <param name="function">Dispatch-table entry; <see langword="null"/> when unbound.</param>
    /// <param name="name">Supplied by the compiler. Do not pass explicitly.</param>
    private static unsafe void ThrowIfUnbound(void* function, [CallerMemberName] string name = "")
    {
        if (function is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, name);
    }

    /// <summary>
    /// Copies a unified attribute template into the Pack=1 Windows layout for the duration of a
    /// single call. Null in, null out: a null template is a legitimate cryptoki argument.
    /// </summary>
    private static CK_ATTRIBUTE_Windows[]? ToWindowsTemplate(ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (template.IsEmpty)
            return null;

        var packed = new CK_ATTRIBUTE_Windows[template.Length];
        for (int i = 0; i < template.Length; i++)
            packed[i] = CK_ATTRIBUTE_Windows.FromUnified(in template[i]);
        return packed;
    }

    // ── Message-AEAD family wrappers (v3.0) ──────────────────────────────────────

    /// <summary>
    /// Resolves the pointer to pass for a nullable, possibly-empty output buffer: <c>null</c> when
    /// <paramref name="buffer"/> itself is <c>null</c> (the length-probe signal), the sentinel address
    /// when it is real but empty (since <c>fixed</c> yields a null pointer for any empty array, and
    /// null would be indistinguishable from the probe signal here), or <paramref name="raw"/> otherwise.
    /// </summary>
    private static unsafe byte* SentinelOrData(byte[]? buffer, byte* raw, byte* sentinel)
    {
        if (buffer is null)
            return null;
        return buffer.Length == 0 ? sentinel : raw;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Delegates"/>. Function pointers are
    /// acquired via <c>C_GetFunctionList</c> against the dynamically loaded library
    /// when <paramref name="libraryHandle"/> is non-zero, or against the host
    /// executable's own symbol table otherwise (a statically-linked module).
    /// </summary>
    /// <param name="libraryHandle">Handle to the dynamically loaded PKCS#11 library,
    /// or <see cref="IntPtr.Zero"/> for a statically-linked library.</param>
    internal Delegates(IntPtr libraryHandle)
        // A statically-linked module's exports live in the entry-point module, which
        // GetMainProgramHandle() resolves against on CoreCLR and Native AOT alike. That makes the
        // static path the ordinary load sequence over a different handle rather than a separate
        // bootstrap: same C_GetFunctionList entry, same best-effort v3.0/v3.2 binding, same
        // graceful degradation for exports a v2.40-only module does not provide.
        => Load(ResolverFor(libraryHandle != IntPtr.Zero
            ? libraryHandle
            : NativeLibrary.GetMainProgramHandle()));

    /// <summary>
    /// Initializes the dispatch table through an export resolver instead of an OS library
    /// handle. This is the hermetic-test seam: production goes through
    /// <see cref="Delegates(IntPtr)"/>, whose resolver wraps <see cref="NativeLibrary.TryGetExport"/>;
    /// tests supply a resolver returning managed <c>[UnmanagedCallersOnly]</c> stubs and
    /// synthetic function-list tables, so the real bootstrap / version-dispatch / slot-binding
    /// logic runs without any native module.
    /// </summary>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal Delegates(Func<string, IntPtr> resolveExport) => Load(resolveExport);

    /// <summary>Dynamic-load sequence: v2.40 bootstrap, then best-effort v3.0/v3.2 binding.</summary>
    private void Load(Func<string, IntPtr> resolveExport)
    {
        InitializeWithGetFunctionList(resolveExport);
        // Best-effort load of v3.0 functions via direct symbol lookup. The full
        // C_GetInterface-based loader path lives in Pkcs11Library / bucket E.
        TryLoadV30Symbols(resolveExport);
    }

    /// <summary>Export resolver over an OS library handle (returns Zero for missing exports).</summary>
    private static Func<string, IntPtr> ResolverFor(IntPtr libraryHandle)
        => name => NativeLibrary.TryGetExport(libraryHandle, name, out IntPtr address) ? address : IntPtr.Zero;

    /// <summary>
    /// Best-effort: bind v3.0 function pointers. Preferred path is C_GetInterface
    /// (v3.0 §5.4.5) which yields a typed CK_FUNCTION_LIST_3_0 carrying every v2.40
    /// pointer plus the v3.0 additions. Fallback path: per-symbol NativeLibrary lookup
    /// against the dynamically loaded library — handles v2.40 tokens (delegates stay
    /// <see langword="null"/>) and v3.0 tokens that export individual symbols but
    /// don't publish the interface table.
    /// </summary>
    private void TryLoadV30Symbols(Func<string, IntPtr> resolveExport)
    {
        // Preferred: ask the library for its v3.0 interface table.
        if (TryLoadFromGetInterface(resolveExport))
            return;

        // Fallback: per-symbol lookup. Works for libraries that export the v3.0
        // functions as plain symbols even though they don't expose C_GetInterface.
        // A missing export resolves to Zero, which each binder treats as "absent".
        BindLoginUser(resolveExport("C_LoginUser"));
        BindSessionCancel(resolveExport("C_SessionCancel"));
        BindGetInterfaceList(resolveExport("C_GetInterfaceList"));

        BindMessageEncryptInit(resolveExport("C_MessageEncryptInit"));
        BindEncryptMessage(resolveExport("C_EncryptMessage"));
        BindEncryptMessageBegin(resolveExport("C_EncryptMessageBegin"));
        BindEncryptMessageNext(resolveExport("C_EncryptMessageNext"));
        BindMessageEncryptFinal(resolveExport("C_MessageEncryptFinal"));

        BindMessageDecryptInit(resolveExport("C_MessageDecryptInit"));
        BindDecryptMessage(resolveExport("C_DecryptMessage"));
        BindDecryptMessageBegin(resolveExport("C_DecryptMessageBegin"));
        BindDecryptMessageNext(resolveExport("C_DecryptMessageNext"));
        BindMessageDecryptFinal(resolveExport("C_MessageDecryptFinal"));

        BindMessageSignInit(resolveExport("C_MessageSignInit"));
        BindSignMessage(resolveExport("C_SignMessage"));
        BindSignMessageBegin(resolveExport("C_SignMessageBegin"));
        BindSignMessageNext(resolveExport("C_SignMessageNext"));
        BindMessageSignFinal(resolveExport("C_MessageSignFinal"));

        BindMessageVerifyInit(resolveExport("C_MessageVerifyInit"));
        BindVerifyMessage(resolveExport("C_VerifyMessage"));
        BindVerifyMessageBegin(resolveExport("C_VerifyMessageBegin"));
        BindVerifyMessageNext(resolveExport("C_VerifyMessageNext"));
        BindMessageVerifyFinal(resolveExport("C_MessageVerifyFinal"));

        BindEncapsulateKey(resolveExport("C_EncapsulateKey"));
        BindDecapsulateKey(resolveExport("C_DecapsulateKey"));
        BindVerifySignatureInit(resolveExport("C_VerifySignatureInit"));
        BindVerifySignature(resolveExport("C_VerifySignature"));
        BindVerifySignatureUpdate(resolveExport("C_VerifySignatureUpdate"));
        BindVerifySignatureFinal(resolveExport("C_VerifySignatureFinal"));
        BindGetSessionValidationFlags(resolveExport("C_GetSessionValidationFlags"));
        BindAsyncComplete(resolveExport("C_AsyncComplete"));
        BindAsyncGetID(resolveExport("C_AsyncGetID"));
        BindAsyncJoin(resolveExport("C_AsyncJoin"));
        BindWrapKeyAuthenticated(resolveExport("C_WrapKeyAuthenticated"));
        BindUnwrapKeyAuthenticated(resolveExport("C_UnwrapKeyAuthenticated"));
    }

    /// <summary>
    /// Tries the preferred v3.0 loader path: call C_GetInterface to obtain the default
    /// "PKCS 11" interface, then read its function table as <see cref="CK_FUNCTION_LIST_3_0"/>
    /// and bind every v3.0 delegate from the table. Returns true on success, false if
    /// C_GetInterface is unavailable / fails / returns a non-3.x version, leaving the
    /// caller to use the per-symbol fallback.
    /// </summary>
    private bool TryLoadFromGetInterface(Func<string, IntPtr> resolveExport)
    {
        if (!TryResolve(resolveExport, "C_GetInterface", out IntPtr getInterfaceRawPtr))
            return false;
        unsafe { _fp.C_GetInterface = (delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)getInterfaceRawPtr; }

        if (!TryGetDefaultInterfaceFunctionList(out IntPtr functionList, out CK_VERSION version))
            return false;

        BindV30FunctionList(UnmanagedMemory.Read<CK_FUNCTION_LIST_3_0>(functionList));

        // v3.2 token: re-read the function table as CK_FUNCTION_LIST_3_2 and bind
        // the 12 v3.2 additions on top of the v3.0 bindings.
        if (version.Minor >= 2)
            BindV32FunctionList(UnmanagedMemory.Read<CK_FUNCTION_LIST_3_2>(functionList));

        return true;
    }

    /// <summary>
    /// Asks the already-bound C_GetInterface for the default interface (null name, null
    /// version, flags = 0) and validates the table it hands back. Yields the function-list
    /// pointer and its CK_VERSION header only for a v3.x table; returns false — with
    /// <paramref name="functionList"/> left at <see cref="IntPtr.Zero"/> — when the call
    /// throws, fails, or returns a v2.40 table the v3.0 binders must not read.
    /// </summary>
    private bool TryGetDefaultInterfaceFunctionList(out IntPtr functionList, out CK_VERSION version)
    {
        functionList = IntPtr.Zero;
        version = default;

        IntPtr interfacePtr;
        NativeCULong rv;
        try
        {
            unsafe { rv = _fp.C_GetInterface(null, IntPtr.Zero, &interfacePtr, new NativeCULong(0)); }
        }
        catch
        {
            return false;
        }

        if (rv.ToCKR() != CKR.CKR_OK || interfacePtr == IntPtr.Zero)
            return false;

        CK_INTERFACE iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        if (iface.FunctionList == IntPtr.Zero)
            return false;

        // The function-list pointer can be either CK_FUNCTION_LIST (v2.40) or
        // CK_FUNCTION_LIST_3_0 (v3.0+). The CK_VERSION header at offset 0 distinguishes
        // them. Read just the version first to decide.
        version = UnmanagedMemory.Read<CK_VERSION>(iface.FunctionList);
        if (version.Major < 3)
            return false;

        functionList = iface.FunctionList;
        return true;
    }

    /// <summary>
    /// Get delegates from unmanaged function pointers
    /// </summary>
    /// <param name="funcList">Structure which contains cryptoki function pointers</param>
    private void Initialize(CK_FUNCTION_LIST funcList)
    {
        unsafe { _fp.C_Initialize = (delegate* unmanaged[Cdecl]<IntPtr, NativeCULong>)funcList.C_Initialize; }
        unsafe { _fp.C_Finalize = (delegate* unmanaged[Cdecl]<IntPtr, NativeCULong>)funcList.C_Finalize; }
        unsafe
        {
            _fp.C_GetInfo = (delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong>)funcList.C_GetInfo;
            _fp.C_GetInfo_Windows = (delegate* unmanaged[Cdecl]<CK_INFO_Windows*, NativeCULong>)funcList.C_GetInfo;
        }
        unsafe { _fp.C_GetFunctionList = (delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)funcList.C_GetFunctionList; }
        unsafe { _fp.C_GetSlotList = (delegate* unmanaged[Cdecl]<byte, NativeCULong*, NativeCULong*, NativeCULong>)funcList.C_GetSlotList; }
        unsafe
        {
            _fp.C_GetSlotInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO*, NativeCULong>)funcList.C_GetSlotInfo;
            _fp.C_GetSlotInfo_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO_Windows*, NativeCULong>)funcList.C_GetSlotInfo;
        }
        unsafe
        {
            _fp.C_GetTokenInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO*, NativeCULong>)funcList.C_GetTokenInfo;
            _fp.C_GetTokenInfo_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO_Windows*, NativeCULong>)funcList.C_GetTokenInfo;
        }
        unsafe { _fp.C_GetMechanismList = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong*, NativeCULong>)funcList.C_GetMechanismList; }
        unsafe
        {
            _fp.C_GetMechanismInfo = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong>)funcList.C_GetMechanismInfo;
            _fp.C_GetMechanismInfo_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO_Windows*, NativeCULong>)funcList.C_GetMechanismInfo;
        }
        unsafe { _fp.C_InitToken = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong>)funcList.C_InitToken; }
        unsafe { _fp.C_InitPIN = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_InitPIN; }
        unsafe { _fp.C_SetPIN = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_SetPIN; }
        unsafe { _fp.C_OpenSession = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, IntPtr, IntPtr, NativeCULong*, NativeCULong>)funcList.C_OpenSession; }
        unsafe { _fp.C_CloseSession = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CloseSession; }
        unsafe { _fp.C_CloseAllSessions = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CloseAllSessions; }
        unsafe
        {
            _fp.C_GetSessionInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong>)funcList.C_GetSessionInfo;
            _fp.C_GetSessionInfo_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO_Windows*, NativeCULong>)funcList.C_GetSessionInfo;
        }
        unsafe { _fp.C_GetOperationState = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_GetOperationState; }
        unsafe { _fp.C_SetOperationState = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong, NativeCULong, NativeCULong>)funcList.C_SetOperationState; }
        unsafe { _fp.C_Login = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_Login; }
        unsafe { _fp.C_Logout = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_Logout; }
        unsafe
        {
            _fp.C_CreateObject = (delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_CreateObject;
            _fp.C_CreateObject_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_CreateObject;
        }
        unsafe
        {
            _fp.C_CopyObject = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_CopyObject;
            _fp.C_CopyObject_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_CopyObject;
        }
        unsafe { _fp.C_DestroyObject = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)funcList.C_DestroyObject; }
        unsafe { _fp.C_GetObjectSize = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_GetObjectSize; }
        unsafe
        {
            _fp.C_GetAttributeValue = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong>)funcList.C_GetAttributeValue;
            _fp.C_GetAttributeValue_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong>)funcList.C_GetAttributeValue;
        }
        unsafe
        {
            _fp.C_SetAttributeValue = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong>)funcList.C_SetAttributeValue;
            _fp.C_SetAttributeValue_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong>)funcList.C_SetAttributeValue;
        }
        unsafe
        {
            _fp.C_FindObjectsInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong>)funcList.C_FindObjectsInit;
            _fp.C_FindObjectsInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong>)funcList.C_FindObjectsInit;
        }
        unsafe { _fp.C_FindObjects = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_FindObjects; }
        unsafe { _fp.C_FindObjectsFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_FindObjectsFinal; }
        unsafe
        {
            _fp.C_EncryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_EncryptInit;
            _fp.C_EncryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_EncryptInit;
        }
        unsafe { _fp.C_Encrypt = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_Encrypt; }
        unsafe { _fp.C_EncryptUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_EncryptUpdate; }
        unsafe { _fp.C_EncryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_EncryptFinal; }
        unsafe
        {
            _fp.C_DecryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_DecryptInit;
            _fp.C_DecryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_DecryptInit;
        }
        unsafe { _fp.C_Decrypt = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_Decrypt; }
        unsafe { _fp.C_DecryptUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DecryptUpdate; }
        unsafe { _fp.C_DecryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DecryptFinal; }
        unsafe
        {
            _fp.C_DigestInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong>)funcList.C_DigestInit;
            _fp.C_DigestInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong>)funcList.C_DigestInit;
        }
        unsafe { _fp.C_Digest = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_Digest; }
        unsafe { _fp.C_DigestUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_DigestUpdate; }
        unsafe { _fp.C_DigestKey = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)funcList.C_DigestKey; }
        unsafe { _fp.C_DigestFinal = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DigestFinal; }
        unsafe
        {
            _fp.C_SignInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_SignInit;
            _fp.C_SignInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_SignInit;
        }
        unsafe { _fp.C_Sign = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_Sign; }
        unsafe { _fp.C_SignUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_SignUpdate; }
        unsafe { _fp.C_SignFinal = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_SignFinal; }
        unsafe
        {
            _fp.C_SignRecoverInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_SignRecoverInit;
            _fp.C_SignRecoverInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_SignRecoverInit;
        }
        unsafe { _fp.C_SignRecover = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_SignRecover; }
        unsafe
        {
            _fp.C_VerifyInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_VerifyInit;
            _fp.C_VerifyInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_VerifyInit;
        }
        unsafe { _fp.C_Verify = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_Verify; }
        unsafe { _fp.C_VerifyUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_VerifyUpdate; }
        unsafe { _fp.C_VerifyFinal = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_VerifyFinal; }
        unsafe
        {
            _fp.C_VerifyRecoverInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)funcList.C_VerifyRecoverInit;
            _fp.C_VerifyRecoverInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)funcList.C_VerifyRecoverInit;
        }
        unsafe { _fp.C_VerifyRecover = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_VerifyRecover; }
        unsafe { _fp.C_DigestEncryptUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DigestEncryptUpdate; }
        unsafe { _fp.C_DecryptDigestUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DecryptDigestUpdate; }
        unsafe { _fp.C_SignEncryptUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_SignEncryptUpdate; }
        unsafe { _fp.C_DecryptVerifyUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_DecryptVerifyUpdate; }
        unsafe
        {
            _fp.C_GenerateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_GenerateKey;
            _fp.C_GenerateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_GenerateKey;
        }
        unsafe
        {
            _fp.C_GenerateKeyPair = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong>)funcList.C_GenerateKeyPair;
            _fp.C_GenerateKeyPair_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong>)funcList.C_GenerateKeyPair;
        }
        unsafe
        {
            _fp.C_WrapKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_WrapKey;
            _fp.C_WrapKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong>)funcList.C_WrapKey;
        }
        unsafe
        {
            _fp.C_UnwrapKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_UnwrapKey;
            _fp.C_UnwrapKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_UnwrapKey;
        }
        unsafe
        {
            _fp.C_DeriveKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_DeriveKey;
            _fp.C_DeriveKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong>)funcList.C_DeriveKey;
        }
        unsafe { _fp.C_SeedRandom = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_SeedRandom; }
        unsafe { _fp.C_GenerateRandom = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)funcList.C_GenerateRandom; }
        unsafe { _fp.C_GetFunctionStatus = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_GetFunctionStatus; }
        unsafe { _fp.C_CancelFunction = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CancelFunction; }
        unsafe { _fp.C_WaitForSlotEvent = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, IntPtr, NativeCULong>)funcList.C_WaitForSlotEvent; }
    }
}
