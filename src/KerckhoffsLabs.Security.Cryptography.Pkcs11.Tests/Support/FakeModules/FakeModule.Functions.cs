using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

// The Cryptoki functions a FakeModule can implement: a virtual per function, taking spans and
// decoded structs, and the [UnmanagedCallersOnly] thunk the function table points at, which decodes
// the raw C arguments (Windows packed layouts included) and writes results back. Add functions here as
// tests need them; a slot stays NULL until a subclass overrides its virtual.
internal abstract unsafe partial class FakeModule
{
    protected virtual CKR C_Initialize(IntPtr pInitArgs) => CKR.CKR_OK;
    protected virtual CKR C_Finalize(IntPtr pReserved) => CKR.CKR_OK;
    protected virtual CKR C_GetInfo(ref CK_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_CloseSession(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Logout(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> digest, ref NativeCULong digestLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;

    private void BindFunctions(Dictionary<string, IntPtr> slots)
    {
        slots[nameof(CryptokiTable.C_Initialize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&Initialize;
        slots[nameof(CryptokiTable.C_Finalize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&FinalizeLibrary;
        if (Overrides(nameof(C_GetInfo)))
            slots[nameof(CryptokiTable.C_GetInfo)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&GetInfo;
        if (Overrides(nameof(C_GetSlotList)))
            slots[nameof(CryptokiTable.C_GetSlotList)] = (IntPtr)(delegate* unmanaged[Cdecl]<byte, NativeCULong*, NativeCULong*, NativeCULong>)&GetSlotList;
        if (Overrides(nameof(C_WaitForSlotEvent)))
            slots[nameof(CryptokiTable.C_WaitForSlotEvent)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, IntPtr, NativeCULong>)&WaitForSlotEvent;
        if (Overrides(nameof(C_GetTokenInfo)))
            slots[nameof(CryptokiTable.C_GetTokenInfo)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong>)&GetTokenInfo;
        if (Overrides(nameof(C_InitToken)))
            slots[nameof(CryptokiTable.C_InitToken)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong>)&InitToken;
        if (Overrides(nameof(C_OpenSession)))
            slots[nameof(CryptokiTable.C_OpenSession)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, void*, NativeCULong*, NativeCULong>)&OpenSession;
        if (Overrides(nameof(C_CloseSession)))
            slots[nameof(CryptokiTable.C_CloseSession)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&CloseSession;
        if (Overrides(nameof(C_Login)))
            slots[nameof(CryptokiTable.C_Login)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, NativeCULong>)&Login;
        if (Overrides(nameof(C_Logout)))
            slots[nameof(CryptokiTable.C_Logout)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&Logout;
        if (Overrides(nameof(C_FindObjectsInit)))
            slots[nameof(CryptokiTable.C_FindObjectsInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&FindObjectsInit;
        if (Overrides(nameof(C_FindObjects)))
            slots[nameof(CryptokiTable.C_FindObjects)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong, NativeCULong*, NativeCULong>)&FindObjects;
        if (Overrides(nameof(C_FindObjectsFinal)))
            slots[nameof(CryptokiTable.C_FindObjectsFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&FindObjectsFinal;
        if (Overrides(nameof(C_GetAttributeValue)))
            slots[nameof(CryptokiTable.C_GetAttributeValue)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong>)&GetAttributeValue;
        if (Overrides(nameof(C_EncryptInit)))
            slots[nameof(CryptokiTable.C_EncryptInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&EncryptInit;
        if (Overrides(nameof(C_Encrypt)))
            slots[nameof(CryptokiTable.C_Encrypt)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&Encrypt;
        if (Overrides(nameof(C_DigestInit)))
            slots[nameof(CryptokiTable.C_DigestInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong>)&DigestInit;
        if (Overrides(nameof(C_Digest)))
            slots[nameof(CryptokiTable.C_Digest)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&Digest;
        if (Overrides(nameof(C_SignInit)))
            slots[nameof(CryptokiTable.C_SignInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&SignInit;
        if (Overrides(nameof(C_Sign)))
            slots[nameof(CryptokiTable.C_Sign)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&Sign;
        if (Overrides(nameof(C_GenerateRandom)))
            slots[nameof(CryptokiTable.C_GenerateRandom)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&GenerateRandom;
    }

    // --- thunks --------------------------------------------------------------------------------
    // Each: find the instance (counting the call), decode, call the virtual, write back, never throw
    // (see RecordFault).

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Initialize(void* pInitArgs)
    {
        if (Active(nameof(C_Initialize)) is not { } m) return Rv(CKR.CKR_GENERAL_ERROR);
        try { return Rv(m.C_Initialize((IntPtr)pInitArgs)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FinalizeLibrary(void* pReserved)
    {
        if (Active(nameof(C_Finalize)) is not { } m) return Rv(CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        try { return Rv(m.C_Finalize((IntPtr)pReserved)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetInfo(void* pInfo)
    {
        if (Active(nameof(C_GetInfo)) is not { } m) return Rv(CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        try
        {
            CK_INFO info = ReadStruct<CK_INFO>(pInfo);
            CKR rv = m.C_GetInfo(ref info);
            WriteStruct(pInfo, in info);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetSlotList(byte tokenPresent, NativeCULong* pSlotList, NativeCULong* pulCount)
    {
        if (Active(nameof(C_GetSlotList)) is not { } m) return Rv(CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        try
        {
            NativeCULong count = *pulCount;
            CKR rv = m.C_GetSlotList(tokenPresent != 0, new NativeBuffer<NativeCULong>(pSlotList, count), ref count);
            *pulCount = count;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong WaitForSlotEvent(NativeCULong flags, NativeCULong* pSlot, IntPtr pReserved)
    {
        if (Active(nameof(C_WaitForSlotEvent)) is not { } m) return Rv(CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        try
        {
            NativeCULong slot = *pSlot;
            CKR rv = m.C_WaitForSlotEvent(flags, ref slot);
            *pSlot = slot;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetTokenInfo(NativeCULong slotId, void* pInfo)
    {
        if (Owner(slotId, nameof(C_GetTokenInfo)) is not { } m) return Rv(CKR.CKR_SLOT_ID_INVALID);
        try
        {
            CK_TOKEN_INFO info = ReadStruct<CK_TOKEN_INFO>(pInfo);
            CKR rv = m.C_GetTokenInfo(slotId, ref info);
            WriteStruct(pInfo, in info);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong OpenSession(NativeCULong slotId, NativeCULong flags, void* pApplication, void* notify, NativeCULong* phSession)
    {
        if (Owner(slotId, nameof(C_OpenSession)) is not { } m) return Rv(CKR.CKR_SLOT_ID_INVALID);
        try
        {
            NativeCULong session = *phSession;
            CKR rv = m.C_OpenSession(slotId, flags, (IntPtr)pApplication, (IntPtr)notify, ref session);
            *phSession = session;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong CloseSession(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_CloseSession)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_CloseSession(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Login(NativeCULong hSession, NativeCULong userType, byte* pPin, NativeCULong ulPinLen)
    {
        if (Owner(hSession, nameof(C_Login)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_Login(hSession, userType, In(pPin, ulPinLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    // pLabel has no length: the spec fixes it at 32 bytes, so that is all the module may read.
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong InitToken(NativeCULong slotId, byte* pPin, NativeCULong ulPinLen, byte* pLabel)
    {
        if (Active(nameof(C_InitToken)) is not { } m) return Rv(CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        try { return Rv(m.C_InitToken(slotId, In(pPin, ulPinLen), In(pLabel, (NativeCULong)32UL))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Logout(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_Logout)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_Logout(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FindObjectsInit(NativeCULong hSession, void* pTemplate, NativeCULong ulCount)
    {
        if (Owner(hSession, nameof(C_FindObjectsInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_FindObjectsInit(hSession, ReadTemplate(pTemplate, ulCount))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FindObjects(NativeCULong hSession, NativeCULong* phObject, NativeCULong ulMaxObjectCount, NativeCULong* pulObjectCount)
    {
        if (Owner(hSession, nameof(C_FindObjects)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong count = default;
            CKR rv = m.C_FindObjects(hSession, new Span<NativeCULong>(phObject, checked((int)(ulong)ulMaxObjectCount)), ref count);
            *pulObjectCount = count;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FindObjectsFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_FindObjectsFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_FindObjectsFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetAttributeValue(NativeCULong hSession, NativeCULong hObject, void* pTemplate, NativeCULong ulCount)
    {
        if (Owner(hSession, nameof(C_GetAttributeValue)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            CK_ATTRIBUTE[] template = ReadTemplate(pTemplate, ulCount);
            CKR rv = m.C_GetAttributeValue(hSession, hObject, template);
            WriteTemplate(pTemplate, template);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_EncryptInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_EncryptInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Encrypt(NativeCULong hSession, byte* pData, NativeCULong ulDataLen, byte* pEncryptedData, NativeCULong* pulEncryptedDataLen)
    {
        if (Owner(hSession, nameof(C_Encrypt)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulEncryptedDataLen;
            CKR rv = m.C_Encrypt(hSession, In(pData, ulDataLen), new NativeBuffer<byte>(pEncryptedData, length), ref length);
            *pulEncryptedDataLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DigestInit(NativeCULong hSession, void* pMechanism)
    {
        if (Owner(hSession, nameof(C_DigestInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_DigestInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Digest(NativeCULong hSession, byte* pData, NativeCULong ulDataLen, byte* pDigest, NativeCULong* pulDigestLen)
    {
        if (Owner(hSession, nameof(C_Digest)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulDigestLen;
            CKR rv = m.C_Digest(hSession, In(pData, ulDataLen), new NativeBuffer<byte>(pDigest, length), ref length);
            *pulDigestLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_SignInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_SignInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Sign(NativeCULong hSession, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong* pulSignatureLen)
    {
        if (Owner(hSession, nameof(C_Sign)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulSignatureLen;
            CKR rv = m.C_Sign(hSession, In(pData, ulDataLen), new NativeBuffer<byte>(pSignature, length), ref length);
            *pulSignatureLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GenerateRandom(NativeCULong hSession, byte* pRandomData, NativeCULong ulRandomLen)
    {
        if (Owner(hSession, nameof(C_GenerateRandom)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_GenerateRandom(hSession, new Span<byte>(pRandomData, checked((int)(ulong)ulRandomLen)))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }
}
