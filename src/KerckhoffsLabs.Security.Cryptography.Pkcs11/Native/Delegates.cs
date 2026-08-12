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
internal class Delegates
{
    /// <summary>
    /// Typed function pointer table. Populated by Initialize / TryLoadV30Symbols /
    /// TryLoadFromGetInterface; every cryptoki function is dispatched through an entry
    /// here plus a wrapper method on this class.
    /// </summary>
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

    /// <summary>Wrapper for <c>C_Initialize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Initialize(IntPtr pInitArgs)
    {
        ThrowIfUnbound(_fp.C_Initialize);
        return _fp.C_Initialize(pInitArgs);
    }

    /// <summary>Wrapper for <c>C_Finalize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Finalize(IntPtr reserved)
    {
        ThrowIfUnbound(_fp.C_Finalize);
        return _fp.C_Finalize(reserved);
    }

    /// <summary>Wrapper for <c>C_GetInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetInfo(ref CK_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetInfo_Windows);
            CK_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetInfo_Windows(&win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetInfo);
        fixed (CK_INFO* p = &info) return _fp.C_GetInfo(p);
    }

    /// <summary>Wrapper for <c>C_GetFunctionList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetFunctionList(out IntPtr functionList)
    {
        ThrowIfUnbound(_fp.C_GetFunctionList);
        IntPtr local = IntPtr.Zero;
        NativeCULong rv = _fp.C_GetFunctionList(&local);
        functionList = local;
        return rv;
    }

    /// <summary>Wrapper for <c>C_GetSlotList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        ThrowIfUnbound(_fp.C_GetSlotList);
        fixed (NativeCULong* slotPtr = slotList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetSlotInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetSlotInfo_Windows);
            CK_SLOT_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetSlotInfo_Windows(slotId, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetSlotInfo);
        fixed (CK_SLOT_INFO* p = &info) return _fp.C_GetSlotInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetTokenInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetTokenInfo_Windows);
            CK_TOKEN_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetTokenInfo_Windows(slotId, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetTokenInfo);
        fixed (CK_TOKEN_INFO* p = &info) return _fp.C_GetTokenInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetMechanismList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetMechanismList(NativeCULong slotId, NativeCULong[]? mechanismList, ref NativeCULong count)
    {
        ThrowIfUnbound(_fp.C_GetMechanismList);
        fixed (NativeCULong* mechPtr = mechanismList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetMechanismList(slotId, mechPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetMechanismInfo_Windows);
            CK_MECHANISM_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetMechanismInfo_Windows(slotId, type, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetMechanismInfo);
        fixed (CK_MECHANISM_INFO* p = &info) return _fp.C_GetMechanismInfo(slotId, type, p);
    }

    /// <summary>Wrapper for <c>C_InitToken</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
    {
        ThrowIfUnbound(_fp.C_InitToken);
        fixed (byte* pinPtr = pin)
        fixed (byte* labelPtr = label)
            return _fp.C_InitToken(slotId, pinPtr, (NativeCULong)pin.Length, labelPtr);
    }

    /// <summary>Wrapper for <c>C_InitPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin)
    {
        ThrowIfUnbound(_fp.C_InitPIN);
        fixed (byte* pinPtr = pin)
            return _fp.C_InitPIN(session, pinPtr, (NativeCULong)pin.Length);
    }

    /// <summary>Wrapper for <c>C_SetPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        ThrowIfUnbound(_fp.C_SetPIN);
        fixed (byte* oldPinPtr = oldPin)
        fixed (byte* newPinPtr = newPin)
            return _fp.C_SetPIN(session, oldPinPtr, (NativeCULong)oldPin.Length, newPinPtr, (NativeCULong)newPin.Length);
    }

    /// <summary>Wrapper for <c>C_OpenSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_OpenSession);
        fixed (NativeCULong* sessionPtr = &session)
            return _fp.C_OpenSession(slotId, flags, application, notify, sessionPtr);
    }

    /// <summary>Wrapper for <c>C_CloseSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseSession(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_CloseSession);
        return _fp.C_CloseSession(session);
    }

    /// <summary>Wrapper for <c>C_CloseAllSessions</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseAllSessions(NativeCULong slotId)
    {
        ThrowIfUnbound(_fp.C_CloseAllSessions);
        return _fp.C_CloseAllSessions(slotId);
    }

    /// <summary>Wrapper for <c>C_GetSessionInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetSessionInfo_Windows);
            CK_SESSION_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetSessionInfo_Windows(session, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetSessionInfo);
        fixed (CK_SESSION_INFO* p = &info) return _fp.C_GetSessionInfo(session, p);
    }

    /// <summary>Wrapper for <c>C_GetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetOperationState(NativeCULong session, Span<byte> operationState, out NativeCULong operationStateLen)
    {
        operationStateLen = (NativeCULong)operationState.Length;
        ThrowIfUnbound(_fp.C_GetOperationState);
        fixed (byte* statePtr = operationState)
        fixed (NativeCULong* lenPtr = &operationStateLen)
            return _fp.C_GetOperationState(session, statePtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey,
        NativeCULong authenticationKey)
    {
        ThrowIfUnbound(_fp.C_SetOperationState);
        fixed (byte* statePtr = operationState)
            return _fp.C_SetOperationState(session, statePtr, (NativeCULong)operationState.Length, encryptionKey, authenticationKey);
    }

    /// <summary>Wrapper for <c>C_Login</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
    {
        ThrowIfUnbound(_fp.C_Login);
        fixed (byte* pinPtr = pin)
            return _fp.C_Login(session, userType, pinPtr, (NativeCULong)pin.Length);
    }

    /// <summary>Wrapper for <c>C_Logout</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Logout(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_Logout);
        return _fp.C_Logout(session);
    }

    /// <summary>Wrapper for <c>C_CreateObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_CreateObject_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* idPtr = &objectId)
                return _fp.C_CreateObject_Windows(session, t, (NativeCULong)template.Length, idPtr);
        }

        ThrowIfUnbound(_fp.C_CreateObject);
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &objectId)
            return _fp.C_CreateObject(session, t, (NativeCULong)template.Length, idPtr);
    }

    /// <summary>Wrapper for <c>C_CopyObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong newObjectId)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_CopyObject_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* idPtr = &newObjectId)
                return _fp.C_CopyObject_Windows(session, objectId, t, (NativeCULong)template.Length, idPtr);
        }

        ThrowIfUnbound(_fp.C_CopyObject);
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &newObjectId)
            return _fp.C_CopyObject(session, objectId, t, (NativeCULong)template.Length, idPtr);
    }

    /// <summary>Wrapper for <c>C_DestroyObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        ThrowIfUnbound(_fp.C_DestroyObject);
        return _fp.C_DestroyObject(session, objectId);
    }

    /// <summary>Wrapper for <c>C_GetObjectSize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        ThrowIfUnbound(_fp.C_GetObjectSize);
        fixed (NativeCULong* sizePtr = &size)
            return _fp.C_GetObjectSize(session, objectId, sizePtr);
    }

    /// <summary>Wrapper for <c>C_GetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetAttributeValue_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            NativeCULong winRv;
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                winRv = _fp.C_GetAttributeValue_Windows(session, objectId, t, (NativeCULong)template.Length);
            // The token writes the value and its length back into the packed copy, so
            // mirror the result into the caller's template before returning.
            if (winTpl is not null)
                for (int i = 0; i < winTpl.Length; i++)
                    template[i] = winTpl[i].ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetAttributeValue);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_GetAttributeValue(session, objectId, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_SetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SetAttributeValue_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                return _fp.C_SetAttributeValue_Windows(session, objectId, t, (NativeCULong)template.Length);
        }

        ThrowIfUnbound(_fp.C_SetAttributeValue);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_SetAttributeValue(session, objectId, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_FindObjectsInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_FindObjectsInit_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                return _fp.C_FindObjectsInit_Windows(session, t, (NativeCULong)template.Length);
        }

        ThrowIfUnbound(_fp.C_FindObjectsInit);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_FindObjectsInit(session, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_FindObjects</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        ThrowIfUnbound(_fp.C_FindObjects);
        fixed (NativeCULong* objPtr = objectId)
        fixed (NativeCULong* countPtr = &objectCount)
            return _fp.C_FindObjects(session, objPtr, maxObjectCount, countPtr);
    }

    /// <summary>Wrapper for <c>C_FindObjectsFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjectsFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_FindObjectsFinal);
        return _fp.C_FindObjectsFinal(session);
    }

    /// <summary>Wrapper for <c>C_EncryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_EncryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_EncryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_EncryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_EncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Encrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, out NativeCULong encryptedDataLen)
    {
        encryptedDataLen = (NativeCULong)encryptedData.Length;
        ThrowIfUnbound(_fp.C_Encrypt);
        fixed (byte* dataPtr = data)
        fixed (byte* encDataPtr = encryptedData)
        fixed (NativeCULong* encLenPtr = &encryptedDataLen)
            return _fp.C_Encrypt(session, dataPtr, (NativeCULong)data.Length, encDataPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen)
    {
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        ThrowIfUnbound(_fp.C_EncryptUpdate);
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* encLenPtr = &encryptedPartLen)
            return _fp.C_EncryptUpdate(session, partPtr, (NativeCULong)part.Length, encPartPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, out NativeCULong lastEncryptedPartLen)
    {
        lastEncryptedPartLen = (NativeCULong)lastEncryptedPart.Length;
        ThrowIfUnbound(_fp.C_EncryptFinal);
        fixed (byte* partPtr = lastEncryptedPart)
        fixed (NativeCULong* lenPtr = &lastEncryptedPartLen)
            return _fp.C_EncryptFinal(session, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DecryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_DecryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_DecryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_DecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Decrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen)
    {
        dataLen = (NativeCULong)data.Length;
        ThrowIfUnbound(_fp.C_Decrypt);
        fixed (byte* encDataPtr = encryptedData)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_Decrypt(session, encDataPtr, (NativeCULong)encryptedData.Length, dataPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen)
    {
        partLen = (NativeCULong)part.Length;
        ThrowIfUnbound(_fp.C_DecryptUpdate);
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptUpdate(session, encPartPtr, (NativeCULong)encryptedPart.Length, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptFinal(NativeCULong session, Span<byte> lastPart, out NativeCULong lastPartLen)
    {
        lastPartLen = (NativeCULong)lastPart.Length;
        ThrowIfUnbound(_fp.C_DecryptFinal);
        fixed (byte* partPtr = lastPart)
        fixed (NativeCULong* lenPtr = &lastPartLen)
            return _fp.C_DecryptFinal(session, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DigestInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_DigestInit_Windows(session, &winMech);
        }

        ThrowIfUnbound(_fp.C_DigestInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_DigestInit(session, m);
    }

    /// <summary>Wrapper for <c>C_Digest</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, out NativeCULong digestLen)
    {
        digestLen = (NativeCULong)digest.Length;
        ThrowIfUnbound(_fp.C_Digest);
        fixed (byte* dataPtr = data)
        fixed (byte* digestPtr = digest)
        fixed (NativeCULong* lenPtr = &digestLen)
            return _fp.C_Digest(session, dataPtr, (NativeCULong)data.Length, digestPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_DigestUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_DigestUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_DigestKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestKey(NativeCULong session, NativeCULong key)
    {
        ThrowIfUnbound(_fp.C_DigestKey);
        return _fp.C_DigestKey(session, key);
    }

    /// <summary>Wrapper for <c>C_DigestFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestFinal(NativeCULong session, Span<byte> digest, out NativeCULong digestLen)
    {
        digestLen = (NativeCULong)digest.Length;
        ThrowIfUnbound(_fp.C_DigestFinal);
        fixed (byte* digestPtr = digest)
        fixed (NativeCULong* lenPtr = &digestLen)
            return _fp.C_DigestFinal(session, digestPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SignInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_SignInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_SignInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Sign</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_Sign);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_Sign(session, dataPtr, (NativeCULong)data.Length, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_SignUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_SignUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_SignFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignFinal(NativeCULong session, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignFinal);
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignFinal(session, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SignRecoverInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_SignRecoverInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_SignRecoverInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignRecover);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignRecover(session, dataPtr, (NativeCULong)data.Length, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_VerifyInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifyInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_VerifyInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_VerifyInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Verify</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_Verify);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_Verify(session, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_VerifyUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_VerifyUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyFinal);
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyFinal(session, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifyRecoverInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_VerifyRecoverInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_VerifyRecoverInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, out NativeCULong dataLen)
    {
        dataLen = (NativeCULong)data.Length;
        ThrowIfUnbound(_fp.C_VerifyRecover);
        fixed (byte* sigPtr = signature)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_VerifyRecover(session, sigPtr, (NativeCULong)signature.Length, dataPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen)
    {
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        ThrowIfUnbound(_fp.C_DigestEncryptUpdate);
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            return _fp.C_DigestEncryptUpdate(session, partPtr, (NativeCULong)part.Length, encPartPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptDigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part,
        out NativeCULong partLen)
    {
        partLen = (NativeCULong)part.Length;
        ThrowIfUnbound(_fp.C_DecryptDigestUpdate);
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptDigestUpdate(session, encPartPtr, (NativeCULong)encryptedPart.Length, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen)
    {
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        ThrowIfUnbound(_fp.C_SignEncryptUpdate);
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            return _fp.C_SignEncryptUpdate(session, partPtr, (NativeCULong)part.Length, encPartPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptVerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part,
        out NativeCULong partLen)
    {
        partLen = (NativeCULong)part.Length;
        ThrowIfUnbound(_fp.C_DecryptVerifyUpdate);
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptVerifyUpdate(session, encPartPtr, (NativeCULong)encryptedPart.Length, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GenerateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_GenerateKey_Windows(session, &winMech, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_GenerateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_GenerateKey(session, m, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKeyPair</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GenerateKeyPair_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winPub = ToWindowsTemplate(publicKeyTemplate);
            CK_ATTRIBUTE_Windows[]? winPriv = ToWindowsTemplate(privateKeyTemplate);
            fixed (CK_ATTRIBUTE_Windows* pub = winPub)
            fixed (CK_ATTRIBUTE_Windows* priv = winPriv)
            fixed (NativeCULong* pubK = &publicKey)
            fixed (NativeCULong* privK = &privateKey)
                return _fp.C_GenerateKeyPair_Windows(session, &winMech, pub, (NativeCULong)publicKeyTemplate.Length, priv, (NativeCULong)privateKeyTemplate.Length, pubK, privK);
        }

        ThrowIfUnbound(_fp.C_GenerateKeyPair);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* pub = publicKeyTemplate)
        fixed (CK_ATTRIBUTE* priv = privateKeyTemplate)
        fixed (NativeCULong* pubK = &publicKey)
        fixed (NativeCULong* privK = &privateKey)
            return _fp.C_GenerateKeyPair(session, m, pub, (NativeCULong)publicKeyTemplate.Length, priv, (NativeCULong)privateKeyTemplate.Length, pubK, privK);
    }

    /// <summary>Wrapper for <c>C_WrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        Span<byte> wrappedKey, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_WrapKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* wkPtr = wrappedKey)
            fixed (NativeCULong* lenPtr = &wrappedKeyLen)
                return _fp.C_WrapKey_Windows(session, &winMech, wrappingKey, key, wkPtr, lenPtr);
        }

        ThrowIfUnbound(_fp.C_WrapKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKey(session, m, wrappingKey, key, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_UnwrapKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (byte* wkPtr = wrappedKey)
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_UnwrapKey_Windows(session, &winMech, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_UnwrapKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKey(session, m, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Wrapper for <c>C_DeriveKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DeriveKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_DeriveKey_Windows(session, &winMech, baseKey, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_DeriveKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_DeriveKey(session, m, baseKey, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Wrapper for <c>C_SeedRandom</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed)
    {
        ThrowIfUnbound(_fp.C_SeedRandom);
        fixed (byte* seedPtr = seed)
            return _fp.C_SeedRandom(session, seedPtr, (NativeCULong)seed.Length);
    }

    /// <summary>Wrapper for <c>C_GenerateRandom</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GenerateRandom(NativeCULong session, Span<byte> randomData)
    {
        ThrowIfUnbound(_fp.C_GenerateRandom);
        fixed (byte* dataPtr = randomData)
            return _fp.C_GenerateRandom(session, dataPtr, (NativeCULong)randomData.Length);
    }

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

    /// <summary>Wrapper for <c>C_WaitForSlotEvent</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        ThrowIfUnbound(_fp.C_WaitForSlotEvent);
        fixed (NativeCULong* slotPtr = &slot)
            return _fp.C_WaitForSlotEvent(flags, slotPtr, reserved);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_LoginUser</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_LoginUser => _fp.C_LoginUser is not null;

    /// <summary>Wrapper for <c>C_LoginUser</c> (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    public unsafe NativeCULong C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        ThrowIfUnbound(_fp.C_LoginUser);
        fixed (byte* pinPtr = pin)
        fixed (byte* userPtr = username)
            return _fp.C_LoginUser(session, userType, pinPtr, (NativeCULong)pin.Length, userPtr, (NativeCULong)username.Length);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SessionCancel</c> (PKCS#11 v3.0+).</summary>
    public unsafe bool IsC_SessionCancelSupported => _fp.C_SessionCancel is not null;

    /// <summary>Wrapper for <c>C_SessionCancel</c> (PKCS#11 v3.0). Throws <see cref="Pkcs11Exception"/> if the loaded library is v2.40 or does not export the symbol.</summary>
    public unsafe NativeCULong C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        ThrowIfUnbound(_fp.C_SessionCancel);
        return _fp.C_SessionCancel(session, flags);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetInterfaceList</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_GetInterfaceList => _fp.C_GetInterfaceList is not null;

    /// <summary>Wrapper for <c>C_GetInterfaceList</c> (PKCS#11 v3.0). Two-call idiom: pass <c>null</c> to get the count.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetInterfaceList_Windows);
            if (interfaces is null)
            {
                fixed (NativeCULong* c = &count)
                    return _fp.C_GetInterfaceList_Windows(null, c);
            }

            var winList = new CK_INTERFACE_Windows[interfaces.Length];
            NativeCULong winRv;
            fixed (CK_INTERFACE_Windows* list = winList)
            fixed (NativeCULong* c = &count)
                winRv = _fp.C_GetInterfaceList_Windows(list, c);
            if (winRv.ToCKR() == CKR.CKR_OK)
                for (int i = 0; i < interfaces.Length; i++)
                    interfaces[i] = winList[i].ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetInterfaceList);
        fixed (CK_INTERFACE* list = interfaces)
        fixed (NativeCULong* c = &count)
            return _fp.C_GetInterfaceList(list, c);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetInterface</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_GetInterface => _fp.C_GetInterface is not null;

    /// <summary>
    /// Wrapper for <c>C_GetInterface</c> (PKCS#11 v3.0). Requests the interface named
    /// <paramref name="interfaceName"/> (a NUL-terminated UTF-8 string, or <c>null</c> for the module's
    /// default interface) and reads back the token-owned <see cref="CK_INTERFACE"/> descriptor (the
    /// version argument is always passed as <c>NULL</c> — any version). The returned struct is read via
    /// <see cref="UnmanagedMemory.Read{T}"/>, which applies the correct platform layout, so no Pack=1
    /// sibling wrapper is needed (unlike <c>C_GetInterfaceList</c>, the token owns the memory and we
    /// only read it).
    /// </summary>
    public unsafe NativeCULong C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface)
    {
        iface = default;
        ThrowIfUnbound(_fp.C_GetInterface);

        IntPtr interfacePtr;
        NativeCULong rv;
        fixed (byte* namePtr = interfaceName)
            rv = _fp.C_GetInterface(namePtr, IntPtr.Zero, &interfacePtr, flags);

        if (rv.ToCKR() == CKR.CKR_OK && interfacePtr != IntPtr.Zero)
            iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        return rv;
    }

    // ── Has* availability properties for optional v3.0/v3.2 functions ─────────────

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageEncryptInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageEncryptInit => _fp.C_MessageEncryptInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessage => _fp.C_EncryptMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessageBegin => _fp.C_EncryptMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessageNext => _fp.C_EncryptMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageEncryptFinal => _fp.C_MessageEncryptFinal is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageDecryptInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageDecryptInit => _fp.C_MessageDecryptInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessage => _fp.C_DecryptMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessageBegin => _fp.C_DecryptMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessageNext => _fp.C_DecryptMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageDecryptFinal => _fp.C_MessageDecryptFinal is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageSignInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageSignInit => _fp.C_MessageSignInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessage => _fp.C_SignMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessageBegin => _fp.C_SignMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessageNext => _fp.C_SignMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageSignFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageSignFinal => _fp.C_MessageSignFinal is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageVerifyInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageVerifyInit => _fp.C_MessageVerifyInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessage => _fp.C_VerifyMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessageBegin => _fp.C_VerifyMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessageNext => _fp.C_VerifyMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageVerifyFinal => _fp.C_MessageVerifyFinal is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncapsulateKey</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_EncapsulateKey => _fp.C_EncapsulateKey is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecapsulateKey</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_DecapsulateKey => _fp.C_DecapsulateKey is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_WrapKeyAuthenticated => _fp.C_WrapKeyAuthenticated is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_UnwrapKeyAuthenticated => _fp.C_UnwrapKeyAuthenticated is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureInit</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureInit => _fp.C_VerifySignatureInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignature</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignature => _fp.C_VerifySignature is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureUpdate => _fp.C_VerifySignatureUpdate is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureFinal => _fp.C_VerifySignatureFinal is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_GetSessionValidationFlags => _fp.C_GetSessionValidationFlags is not null;

    // ── Message-AEAD family wrappers (v3.0) ──────────────────────────────────────

    /// <summary>Wrapper for <c>C_MessageEncryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageEncryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageEncryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageEncryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageEncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_EncryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out NativeCULong ciphertextLen)
    {
        ciphertextLen = (NativeCULong)ciphertext.Length;
        ThrowIfUnbound(_fp.C_EncryptMessage);
        fixed (byte* adPtr = associatedData)
        fixed (byte* ptPtr = plaintext)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
            return _fp.C_EncryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length, ptPtr, (NativeCULong)plaintext.Length, ctPtr, ctLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData)
    {
        ThrowIfUnbound(_fp.C_EncryptMessageBegin);
        fixed (byte* adPtr = associatedData)
            return _fp.C_EncryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length);
    }

    /// <summary>Wrapper for <c>C_EncryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, out NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        ciphertextPartLen = (NativeCULong)ciphertextPart.Length;
        ThrowIfUnbound(_fp.C_EncryptMessageNext);
        fixed (byte* ptPtr = plaintextPart)
        fixed (byte* ctPtr = ciphertextPart)
        fixed (NativeCULong* ctLenPtr = &ciphertextPartLen)
            return _fp.C_EncryptMessageNext(session, parameter, parameterLen, ptPtr, (NativeCULong)plaintextPart.Length, ctPtr, ctLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageEncryptFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageEncryptFinal);
        return _fp.C_MessageEncryptFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageDecryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageDecryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageDecryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageDecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_DecryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out NativeCULong plaintextLen)
    {
        plaintextLen = (NativeCULong)plaintext.Length;
        ThrowIfUnbound(_fp.C_DecryptMessage);
        fixed (byte* adPtr = associatedData)
        fixed (byte* ctPtr = ciphertext)
        fixed (byte* ptPtr = plaintext)
        fixed (NativeCULong* ptLenPtr = &plaintextLen)
            return _fp.C_DecryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length, ctPtr, (NativeCULong)ciphertext.Length, ptPtr, ptLenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData)
    {
        ThrowIfUnbound(_fp.C_DecryptMessageBegin);
        fixed (byte* adPtr = associatedData)
            return _fp.C_DecryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length);
    }

    /// <summary>Wrapper for <c>C_DecryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, out NativeCULong plaintextPartLen, NativeCULong flags)
    {
        plaintextPartLen = (NativeCULong)plaintextPart.Length;
        ThrowIfUnbound(_fp.C_DecryptMessageNext);
        fixed (byte* ctPtr = ciphertextPart)
        fixed (byte* ptPtr = plaintextPart)
        fixed (NativeCULong* ptLenPtr = &plaintextPartLen)
            return _fp.C_DecryptMessageNext(session, parameter, parameterLen, ctPtr, (NativeCULong)ciphertextPart.Length, ptPtr, ptLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageDecryptFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageDecryptFinal);
        return _fp.C_MessageDecryptFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageSignInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageSignInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageSignInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageSignInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageSignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignMessage);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_SignMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ThrowIfUnbound(_fp.C_SignMessageBegin);
        return _fp.C_SignMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_SignMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignMessageNext);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_MessageSignFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageSignFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageSignFinal);
        return _fp.C_MessageSignFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageVerifyInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageVerifyInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageVerifyInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageVerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyMessage);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ThrowIfUnbound(_fp.C_VerifyMessageBegin);
        return _fp.C_VerifyMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyMessageNext);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageVerifyFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageVerifyFinal);
        return _fp.C_MessageVerifyFinal(session);
    }

    // ── v3.2 PQC / signature / async / authenticated-wrap wrappers ───────────────

    /// <summary>Wrapper for <c>C_EncapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ciphertextLen = (NativeCULong)ciphertext.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_EncapsulateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* ctPtr = ciphertext)
            fixed (NativeCULong* ctLenPtr = &ciphertextLen)
            fixed (NativeCULong* dkPtr = &derivedKey)
                return _fp.C_EncapsulateKey_Windows(session, &winMech, publicKey, t, (NativeCULong)template.Length, ctPtr, ctLenPtr, dkPtr);
        }

        ThrowIfUnbound(_fp.C_EncapsulateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_EncapsulateKey(session, m, publicKey, t, (NativeCULong)template.Length, ctPtr, ctLenPtr, dkPtr);
    }

    /// <summary>Wrapper for <c>C_DecapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DecapsulateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* ctPtr = ciphertext)
            fixed (NativeCULong* dkPtr = &derivedKey)
                return _fp.C_DecapsulateKey_Windows(session, &winMech, privateKey, t, (NativeCULong)template.Length, ctPtr, (NativeCULong)ciphertext.Length, dkPtr);
        }

        ThrowIfUnbound(_fp.C_DecapsulateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_DecapsulateKey(session, m, privateKey, t, (NativeCULong)template.Length, ctPtr, (NativeCULong)ciphertext.Length, dkPtr);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureInit</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifySignatureInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* sigPtr = signature)
                return _fp.C_VerifySignatureInit_Windows(session, &winMech, key, sigPtr, (NativeCULong)signature.Length);
        }

        ThrowIfUnbound(_fp.C_VerifySignatureInit);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifySignatureInit(session, m, key, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignature</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data)
    {
        ThrowIfUnbound(_fp.C_VerifySignature);
        fixed (byte* dataPtr = data)
            return _fp.C_VerifySignature(session, dataPtr, (NativeCULong)data.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_VerifySignatureUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_VerifySignatureUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_VerifySignatureFinal);
        return _fp.C_VerifySignatureFinal(session);
    }

    /// <summary>Wrapper for <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        ThrowIfUnbound(_fp.C_GetSessionValidationFlags);
        fixed (NativeCULong* flagsPtr = &flags)
            return _fp.C_GetSessionValidationFlags(session, type, flagsPtr);
    }

    /// <summary>Wrapper for <c>C_AsyncComplete</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_AsyncComplete_Windows);
            CK_ASYNC_DATA_Windows win = default;
            NativeCULong winRv;
            fixed (byte* fnPtr = functionName)
                winRv = _fp.C_AsyncComplete_Windows(session, fnPtr, &win);
            result = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_AsyncComplete);
        fixed (byte* fnPtr = functionName)
        fixed (CK_ASYNC_DATA* rPtr = &result)
            return _fp.C_AsyncComplete(session, fnPtr, rPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncComplete</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncComplete => _fp.C_AsyncComplete is not null;

    /// <summary>Wrapper for <c>C_AsyncGetID</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id)
    {
        ThrowIfUnbound(_fp.C_AsyncGetID);
        fixed (byte* fnPtr = functionName)
        fixed (NativeCULong* idPtr = &id)
            return _fp.C_AsyncGetID(session, fnPtr, idPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncGetID</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncGetID => _fp.C_AsyncGetID is not null;

    /// <summary>Wrapper for <c>C_AsyncJoin</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data)
    {
        ThrowIfUnbound(_fp.C_AsyncJoin);
        fixed (byte* fnPtr = functionName)
        fixed (byte* dataPtr = data)
            return _fp.C_AsyncJoin(session, fnPtr, id, dataPtr, (NativeCULong)data.Length);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncJoin</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncJoin => _fp.C_AsyncJoin is not null;

    /// <summary>Wrapper for <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_WrapKeyAuthenticated_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* adPtr = associatedData)
            fixed (byte* wkPtr = wrappedKey)
            fixed (NativeCULong* lenPtr = &wrappedKeyLen)
                return _fp.C_WrapKeyAuthenticated_Windows(session, &winMech, wrappingKey, key, adPtr, (NativeCULong)associatedData.Length, wkPtr, lenPtr);
        }

        ThrowIfUnbound(_fp.C_WrapKeyAuthenticated);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* adPtr = associatedData)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKeyAuthenticated(session, m, wrappingKey, key, adPtr, (NativeCULong)associatedData.Length, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_UnwrapKeyAuthenticated_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (byte* wkPtr = wrappedKey)
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* adPtr = associatedData)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_UnwrapKeyAuthenticated_Windows(session, &winMech, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, adPtr, (NativeCULong)associatedData.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_UnwrapKeyAuthenticated);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* adPtr = associatedData)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKeyAuthenticated(session, m, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, adPtr, (NativeCULong)associatedData.Length, kPtr);
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

    /// <summary>Resolves <paramref name="name"/> and reports whether it is present.</summary>
    private static bool TryResolve(Func<string, IntPtr> resolveExport, string name, out IntPtr address)
    {
        address = resolveExport(name);
        return address != IntPtr.Zero;
    }

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
