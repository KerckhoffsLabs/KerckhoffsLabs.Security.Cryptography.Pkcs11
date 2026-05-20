using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;


/// <summary>
/// Holds delegates for all PKCS#11 functions
/// </summary>
internal partial class Delegates
{
    /// <summary>
    /// Typed function pointer table. Populated by Initialize / TryLoadV30Symbols /
    /// TryLoadFromGetInterface alongside the legacy delegate fields. Migration target
    /// for BL-060 — every delegate field is being replaced by an entry here plus a
    /// wrapper method on this class.
    /// </summary>
    internal readonly FunctionPointers _fp = new();

    /// <summary>
    /// Definition of unmanaged methods (used on iOS)
    /// </summary>
    private static partial class NativeMethods
    {
        /// <summary>
        /// Bootstrap entry point for the statically-linked path. Returns a function
        /// list whose entries are unmanaged function pointers; <see cref="Delegates"/>
        /// then resolves all 67 other cryptoki functions through that table — no
        /// further <c>DllImport</c> declarations are needed.
        /// </summary>
        // Source-generated P/Invoke. Viable because [assembly: DisableRuntimeMarshalling]
        // (see AssemblyAttributes.cs) lets LibraryImport marshal the blittable NativeCULong
        // return + out IntPtr without runtime marshalling.
        [LibraryImport("__Internal")]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        internal static partial NativeCULong C_GetFunctionList(out IntPtr functionList);
    }

    /// <summary>Wrapper for <c>C_Initialize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Initialize(IntPtr pInitArgs)
    {
        if (_fp.C_Initialize is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Initialize");
        return _fp.C_Initialize(pInitArgs);
    }

    /// <summary>Wrapper for <c>C_Finalize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Finalize(IntPtr reserved)
    {
        if (_fp.C_Finalize is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Finalize");
        return _fp.C_Finalize(reserved);
    }

    /// <summary>Wrapper for <c>C_GetInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetInfo(ref CK_INFO info)
    {
        if (_fp.C_GetInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetInfo");
        fixed (CK_INFO* p = &info) return _fp.C_GetInfo(p);
    }

    /// <summary>Wrapper for <c>C_GetInfo</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetInfo_Windows(ref CK_INFO_Windows info)
    {
        if (_fp.C_GetInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetInfo_Windows");
        fixed (CK_INFO_Windows* p = &info) return _fp.C_GetInfo_Windows(p);
    }

    /// <summary>Returns <c>true</c> when the Windows-layout <c>C_GetInfo</c> fptr is bound.</summary>
    internal unsafe bool HasC_GetInfo_Windows => _fp.C_GetInfo_Windows is not null;

    /// <summary>Wrapper for <c>C_GetFunctionList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetFunctionList(out IntPtr functionList)
    {
        if (_fp.C_GetFunctionList is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetFunctionList");
        IntPtr local = IntPtr.Zero;
        NativeCULong rv = _fp.C_GetFunctionList(&local);
        functionList = local;
        return rv;
    }

    /// <summary>Wrapper for <c>C_GetSlotList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        if (_fp.C_GetSlotList is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSlotList");
        fixed (NativeCULong* slotPtr = slotList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetSlotInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        if (_fp.C_GetSlotInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSlotInfo");
        fixed (CK_SLOT_INFO* p = &info) return _fp.C_GetSlotInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetSlotInfo</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetSlotInfo_Windows(NativeCULong slotId, ref CK_SLOT_INFO_Windows info)
    {
        if (_fp.C_GetSlotInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSlotInfo_Windows");
        fixed (CK_SLOT_INFO_Windows* p = &info) return _fp.C_GetSlotInfo_Windows(slotId, p);
    }

    /// <summary>Returns <c>true</c> when the Windows-layout <c>C_GetSlotInfo</c> fptr is bound.</summary>
    internal unsafe bool HasC_GetSlotInfo_Windows => _fp.C_GetSlotInfo_Windows is not null;

    /// <summary>Wrapper for <c>C_GetTokenInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        if (_fp.C_GetTokenInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetTokenInfo");
        fixed (CK_TOKEN_INFO* p = &info) return _fp.C_GetTokenInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetTokenInfo</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetTokenInfo_Windows(NativeCULong slotId, ref CK_TOKEN_INFO_Windows info)
    {
        if (_fp.C_GetTokenInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetTokenInfo_Windows");
        fixed (CK_TOKEN_INFO_Windows* p = &info) return _fp.C_GetTokenInfo_Windows(slotId, p);
    }

    /// <summary>Returns <c>true</c> when the Windows-layout <c>C_GetTokenInfo</c> fptr is bound.</summary>
    internal unsafe bool HasC_GetTokenInfo_Windows => _fp.C_GetTokenInfo_Windows is not null;

    /// <summary>Wrapper for <c>C_GetMechanismList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetMechanismList(NativeCULong slotId, NativeCULong[]? mechanismList, ref NativeCULong count)
    {
        if (_fp.C_GetMechanismList is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetMechanismList");
        fixed (NativeCULong* mechPtr = mechanismList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetMechanismList(slotId, mechPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
    {
        if (_fp.C_GetMechanismInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetMechanismInfo");
        fixed (CK_MECHANISM_INFO* p = &info) return _fp.C_GetMechanismInfo(slotId, type, p);
    }

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetMechanismInfo_Windows(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO_Windows info)
    {
        if (_fp.C_GetMechanismInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetMechanismInfo_Windows");
        fixed (CK_MECHANISM_INFO_Windows* p = &info) return _fp.C_GetMechanismInfo_Windows(slotId, type, p);
    }

    /// <summary>Returns <c>true</c> when the Windows-layout <c>C_GetMechanismInfo</c> fptr is bound.</summary>
    internal unsafe bool HasC_GetMechanismInfo_Windows => _fp.C_GetMechanismInfo_Windows is not null;

    /// <summary>Wrapper for <c>C_InitToken</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label)
    {
        if (_fp.C_InitToken is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_InitToken");
        fixed (byte* pinPtr = pin)
        fixed (byte* labelPtr = label)
            return _fp.C_InitToken(slotId, pinPtr, pinLen, labelPtr);
    }

    /// <summary>Wrapper for <c>C_InitPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen)
    {
        if (_fp.C_InitPIN is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_InitPIN");
        fixed (byte* pinPtr = pin)
            return _fp.C_InitPIN(session, pinPtr, pinLen);
    }

    /// <summary>Wrapper for <c>C_SetPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen)
    {
        if (_fp.C_SetPIN is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SetPIN");
        fixed (byte* oldPinPtr = oldPin)
        fixed (byte* newPinPtr = newPin)
            return _fp.C_SetPIN(session, oldPinPtr, oldPinLen, newPinPtr, newPinLen);
    }

    /// <summary>Wrapper for <c>C_OpenSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        if (_fp.C_OpenSession is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_OpenSession");
        fixed (NativeCULong* sessionPtr = &session)
            return _fp.C_OpenSession(slotId, flags, application, notify, sessionPtr);
    }

    /// <summary>Wrapper for <c>C_CloseSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseSession(NativeCULong session)
    {
        if (_fp.C_CloseSession is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CloseSession");
        return _fp.C_CloseSession(session);
    }

    /// <summary>Wrapper for <c>C_CloseAllSessions</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseAllSessions(NativeCULong slotId)
    {
        if (_fp.C_CloseAllSessions is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CloseAllSessions");
        return _fp.C_CloseAllSessions(slotId);
    }

    /// <summary>Wrapper for <c>C_GetSessionInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        if (_fp.C_GetSessionInfo is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionInfo");
        fixed (CK_SESSION_INFO* p = &info) return _fp.C_GetSessionInfo(session, p);
    }

    /// <summary>Wrapper for <c>C_GetSessionInfo</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetSessionInfo_Windows(NativeCULong session, ref CK_SESSION_INFO_Windows info)
    {
        if (_fp.C_GetSessionInfo_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionInfo_Windows");
        fixed (CK_SESSION_INFO_Windows* p = &info) return _fp.C_GetSessionInfo_Windows(session, p);
    }

    /// <summary>Returns <c>true</c> when the Windows-layout <c>C_GetSessionInfo</c> fptr is bound.</summary>
    internal unsafe bool HasC_GetSessionInfo_Windows => _fp.C_GetSessionInfo_Windows is not null;

    /// <summary>Wrapper for <c>C_GetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetOperationState(NativeCULong session, byte[] operationState, ref NativeCULong operationStateLen)
    {
        if (_fp.C_GetOperationState is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetOperationState");
        fixed (byte* statePtr = operationState)
        fixed (NativeCULong* lenPtr = &operationStateLen)
            return _fp.C_GetOperationState(session, statePtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey)
    {
        if (_fp.C_SetOperationState is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SetOperationState");
        fixed (byte* statePtr = operationState)
            return _fp.C_SetOperationState(session, statePtr, operationStateLen, encryptionKey, authenticationKey);
    }

    /// <summary>Wrapper for <c>C_Login</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Login(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen)
    {
        if (_fp.C_Login is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Login");
        fixed (byte* pinPtr = pin)
            return _fp.C_Login(session, userType, pinPtr, pinLen);
    }

    /// <summary>Wrapper for <c>C_Logout</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Logout(NativeCULong session)
    {
        if (_fp.C_Logout is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Logout");
        return _fp.C_Logout(session);
    }

    /// <summary>Wrapper for <c>C_CreateObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong objectId)
    {
        if (_fp.C_CreateObject is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CreateObject");
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &objectId)
            return _fp.C_CreateObject(session, t, count, idPtr);
    }

    /// <summary>Wrapper for <c>C_CopyObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong newObjectId)
    {
        if (_fp.C_CopyObject is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CopyObject");
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &newObjectId)
            return _fp.C_CopyObject(session, objectId, t, count, idPtr);
    }

    /// <summary>Wrapper for <c>C_DestroyObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        if (_fp.C_DestroyObject is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DestroyObject");
        return _fp.C_DestroyObject(session, objectId);
    }

    /// <summary>Wrapper for <c>C_GetObjectSize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        if (_fp.C_GetObjectSize is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetObjectSize");
        fixed (NativeCULong* sizePtr = &size)
            return _fp.C_GetObjectSize(session, objectId, sizePtr);
    }

    /// <summary>Wrapper for <c>C_GetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        if (_fp.C_GetAttributeValue is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetAttributeValue");
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_GetAttributeValue(session, objectId, t, count);
    }

    /// <summary>Wrapper for <c>C_SetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        if (_fp.C_SetAttributeValue is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SetAttributeValue");
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_SetAttributeValue(session, objectId, t, count);
    }

    /// <summary>Wrapper for <c>C_FindObjectsInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        if (_fp.C_FindObjectsInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_FindObjectsInit");
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_FindObjectsInit(session, t, count);
    }

    /// <summary>Wrapper for <c>C_FindObjects</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        if (_fp.C_FindObjects is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_FindObjects");
        fixed (NativeCULong* objPtr = objectId)
        fixed (NativeCULong* countPtr = &objectCount)
            return _fp.C_FindObjects(session, objPtr, maxObjectCount, countPtr);
    }

    /// <summary>Wrapper for <c>C_FindObjectsFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjectsFinal(NativeCULong session)
    {
        if (_fp.C_FindObjectsFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_FindObjectsFinal");
        return _fp.C_FindObjectsFinal(session);
    }

    /// <summary>Wrapper for <c>C_EncryptInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_EncryptInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_EncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Encrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] encryptedData, ref NativeCULong encryptedDataLen)
    {
        if (_fp.C_Encrypt is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Encrypt");
        fixed (byte* dataPtr = data)
        fixed (byte* encDataPtr = encryptedData)
        fixed (NativeCULong* encLenPtr = &encryptedDataLen)
            return _fp.C_Encrypt(session, dataPtr, dataLen, encDataPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        if (_fp.C_EncryptUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptUpdate");
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* encLenPtr = &encryptedPartLen)
            return _fp.C_EncryptUpdate(session, partPtr, partLen, encPartPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptFinal(NativeCULong session, byte[] lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
    {
        if (_fp.C_EncryptFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptFinal");
        fixed (byte* partPtr = lastEncryptedPart)
        fixed (NativeCULong* lenPtr = &lastEncryptedPartLen)
            return _fp.C_EncryptFinal(session, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_DecryptInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_DecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Decrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[] data, ref NativeCULong dataLen)
    {
        if (_fp.C_Decrypt is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Decrypt");
        fixed (byte* encDataPtr = encryptedData)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_Decrypt(session, encDataPtr, encryptedDataLen, dataPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        if (_fp.C_DecryptUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptUpdate");
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptUpdate(session, encPartPtr, encryptedPartLen, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptFinal(NativeCULong session, byte[] lastPart, ref NativeCULong lastPartLen)
    {
        if (_fp.C_DecryptFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptFinal");
        fixed (byte* partPtr = lastPart)
        fixed (NativeCULong* lenPtr = &lastPartLen)
            return _fp.C_DecryptFinal(session, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        if (_fp.C_DigestInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_DigestInit(session, m);
    }

    /// <summary>Wrapper for <c>C_Digest</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] digest, ref NativeCULong digestLen)
    {
        if (_fp.C_Digest is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Digest");
        fixed (byte* dataPtr = data)
        fixed (byte* digestPtr = digest)
        fixed (NativeCULong* lenPtr = &digestLen)
            return _fp.C_Digest(session, dataPtr, dataLen, digestPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        if (_fp.C_DigestUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestUpdate");
        fixed (byte* partPtr = part)
            return _fp.C_DigestUpdate(session, partPtr, partLen);
    }

    /// <summary>Wrapper for <c>C_DigestKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestKey(NativeCULong session, NativeCULong key)
    {
        if (_fp.C_DigestKey is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestKey");
        return _fp.C_DigestKey(session, key);
    }

    /// <summary>Wrapper for <c>C_DigestFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestFinal(NativeCULong session, byte[] digest, ref NativeCULong digestLen)
    {
        if (_fp.C_DigestFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestFinal");
        fixed (byte* digestPtr = digest)
        fixed (NativeCULong* lenPtr = &digestLen)
            return _fp.C_DigestFinal(session, digestPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_SignInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Sign</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen)
    {
        if (_fp.C_Sign is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Sign");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_Sign(session, dataPtr, dataLen, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        if (_fp.C_SignUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignUpdate");
        fixed (byte* partPtr = part)
            return _fp.C_SignUpdate(session, partPtr, partLen);
    }

    /// <summary>Wrapper for <c>C_SignFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignFinal(NativeCULong session, byte[] signature, ref NativeCULong signatureLen)
    {
        if (_fp.C_SignFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignFinal");
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignFinal(session, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_SignRecoverInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignRecoverInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen)
    {
        if (_fp.C_SignRecover is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignRecover");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignRecover(session, dataPtr, dataLen, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_VerifyInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_VerifyInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Verify</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_Verify is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Verify");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_Verify(session, dataPtr, dataLen, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_VerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        if (_fp.C_VerifyUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyUpdate");
        fixed (byte* partPtr = part)
            return _fp.C_VerifyUpdate(session, partPtr, partLen);
    }

    /// <summary>Wrapper for <c>C_VerifyFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_VerifyFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyFinal");
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyFinal(session, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_VerifyRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_VerifyRecoverInit is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyRecoverInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[] data, ref NativeCULong dataLen)
    {
        if (_fp.C_VerifyRecover is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyRecover");
        fixed (byte* sigPtr = signature)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_VerifyRecover(session, sigPtr, signatureLen, dataPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DigestEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        if (_fp.C_DigestEncryptUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestEncryptUpdate");
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            return _fp.C_DigestEncryptUpdate(session, partPtr, partLen, encPartPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptDigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        if (_fp.C_DecryptDigestUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptDigestUpdate");
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptDigestUpdate(session, encPartPtr, encryptedPartLen, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        if (_fp.C_SignEncryptUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignEncryptUpdate");
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            return _fp.C_SignEncryptUpdate(session, partPtr, partLen, encPartPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptVerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        if (_fp.C_DecryptVerifyUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptVerifyUpdate");
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptVerifyUpdate(session, encPartPtr, encryptedPartLen, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key)
    {
        if (_fp.C_GenerateKey is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_GenerateKey(session, m, t, count, kPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKeyPair</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism,
        CK_ATTRIBUTE[] publicKeyTemplate, NativeCULong publicKeyAttributeCount,
        CK_ATTRIBUTE[] privateKeyTemplate, NativeCULong privateKeyAttributeCount,
        ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        if (_fp.C_GenerateKeyPair is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKeyPair");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* pub = publicKeyTemplate)
        fixed (CK_ATTRIBUTE* priv = privateKeyTemplate)
        fixed (NativeCULong* pubK = &publicKey)
        fixed (NativeCULong* privK = &privateKey)
            return _fp.C_GenerateKeyPair(session, m, pub, publicKeyAttributeCount, priv, privateKeyAttributeCount, pubK, privK);
    }

    /// <summary>Wrapper for <c>C_WrapKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        if (_fp.C_WrapKey is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_WrapKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKey(session, m, wrappingKey, key, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key)
    {
        if (_fp.C_UnwrapKey is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_UnwrapKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKey(session, m, unwrappingKey, wkPtr, wrappedKeyLen, t, attributeCount, kPtr);
    }

    /// <summary>Wrapper for <c>C_DeriveKey</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key)
    {
        if (_fp.C_DeriveKey is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DeriveKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_DeriveKey(session, m, baseKey, t, attributeCount, kPtr);
    }

    /// <summary>Wrapper for <c>C_SeedRandom</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen)
    {
        if (_fp.C_SeedRandom is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SeedRandom");
        fixed (byte* seedPtr = seed)
            return _fp.C_SeedRandom(session, seedPtr, seedLen);
    }

    /// <summary>Wrapper for <c>C_GenerateRandom</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
    {
        if (_fp.C_GenerateRandom is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateRandom");
        fixed (byte* dataPtr = randomData)
            return _fp.C_GenerateRandom(session, dataPtr, randomLen);
    }

    /// <summary>Wrapper for <c>C_GetFunctionStatus</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetFunctionStatus(NativeCULong session)
    {
        if (_fp.C_GetFunctionStatus is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetFunctionStatus");
        return _fp.C_GetFunctionStatus(session);
    }

    /// <summary>Wrapper for <c>C_CancelFunction</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CancelFunction(NativeCULong session)
    {
        if (_fp.C_CancelFunction is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CancelFunction");
        return _fp.C_CancelFunction(session);
    }

    /// <summary>Wrapper for <c>C_WaitForSlotEvent</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        if (_fp.C_WaitForSlotEvent is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_WaitForSlotEvent");
        fixed (NativeCULong* slotPtr = &slot)
            return _fp.C_WaitForSlotEvent(flags, slotPtr, reserved);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_LoginUser</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_LoginUser => _fp.C_LoginUser is not null;

    /// <summary>Wrapper for <c>C_LoginUser</c> (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    public unsafe NativeCULong C_LoginUser(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen)
    {
        if (_fp.C_LoginUser is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_LoginUser");
        fixed (byte* pinPtr = pin)
        fixed (byte* userPtr = username)
            return _fp.C_LoginUser(session, userType, pinPtr, pinLen, userPtr, usernameLen);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SessionCancel</c> (PKCS#11 v3.0+).</summary>
    public unsafe bool IsC_SessionCancelSupported => _fp.C_SessionCancel is not null;

    /// <summary>Wrapper for <c>C_SessionCancel</c> (PKCS#11 v3.0). Throws <see cref="Pkcs11Exception"/> if the loaded library is v2.40 or does not export the symbol.</summary>
    public unsafe NativeCULong C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        if (_fp.C_SessionCancel is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SessionCancel");
        return _fp.C_SessionCancel(session, flags);
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
    public unsafe NativeCULong C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_MessageEncryptInit is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageEncryptInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageEncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_EncryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen)
    {
        if (_fp.C_EncryptMessage is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptMessage");
        fixed (byte* adPtr = associatedData)
        fixed (byte* ptPtr = plaintext)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
            return _fp.C_EncryptMessage(session, parameter, parameterLen, adPtr, associatedDataLen, ptPtr, plaintextLen, ctPtr, ctLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen)
    {
        if (_fp.C_EncryptMessageBegin is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptMessageBegin");
        fixed (byte* adPtr = associatedData)
            return _fp.C_EncryptMessageBegin(session, parameter, parameterLen, adPtr, associatedDataLen);
    }

    /// <summary>Wrapper for <c>C_EncryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        if (_fp.C_EncryptMessageNext is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptMessageNext");
        fixed (byte* ptPtr = plaintextPart)
        fixed (byte* ctPtr = ciphertextPart)
        fixed (NativeCULong* ctLenPtr = &ciphertextPartLen)
            return _fp.C_EncryptMessageNext(session, parameter, parameterLen, ptPtr, plaintextPartLen, ctPtr, ctLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageEncryptFinal(NativeCULong session)
    {
        if (_fp.C_MessageEncryptFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageEncryptFinal");
        return _fp.C_MessageEncryptFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_MessageDecryptInit is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageDecryptInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageDecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_DecryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen)
    {
        if (_fp.C_DecryptMessage is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptMessage");
        fixed (byte* adPtr = associatedData)
        fixed (byte* ctPtr = ciphertext)
        fixed (byte* ptPtr = plaintext)
        fixed (NativeCULong* ptLenPtr = &plaintextLen)
            return _fp.C_DecryptMessage(session, parameter, parameterLen, adPtr, associatedDataLen, ctPtr, ciphertextLen, ptPtr, ptLenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen)
    {
        if (_fp.C_DecryptMessageBegin is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptMessageBegin");
        fixed (byte* adPtr = associatedData)
            return _fp.C_DecryptMessageBegin(session, parameter, parameterLen, adPtr, associatedDataLen);
    }

    /// <summary>Wrapper for <c>C_DecryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags)
    {
        if (_fp.C_DecryptMessageNext is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptMessageNext");
        fixed (byte* ctPtr = ciphertextPart)
        fixed (byte* ptPtr = plaintextPart)
        fixed (NativeCULong* ptLenPtr = &plaintextPartLen)
            return _fp.C_DecryptMessageNext(session, parameter, parameterLen, ctPtr, ciphertextPartLen, ptPtr, ptLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageDecryptFinal(NativeCULong session)
    {
        if (_fp.C_MessageDecryptFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageDecryptFinal");
        return _fp.C_MessageDecryptFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageSignInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_MessageSignInit is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageSignInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageSignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen)
    {
        if (_fp.C_SignMessage is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignMessage");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessage(session, parameter, parameterLen, dataPtr, dataLen, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_SignMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        if (_fp.C_SignMessageBegin is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignMessageBegin");
        return _fp.C_SignMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_SignMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen)
    {
        if (_fp.C_SignMessageNext is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignMessageNext");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessageNext(session, parameter, parameterLen, dataPtr, dataLen, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_MessageSignFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageSignFinal(NativeCULong session)
    {
        if (_fp.C_MessageSignFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageSignFinal");
        return _fp.C_MessageSignFinal(session);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (_fp.C_MessageVerifyInit is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageVerifyInit");
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageVerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_VerifyMessage is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyMessage");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessage(session, parameter, parameterLen, dataPtr, dataLen, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        if (_fp.C_VerifyMessageBegin is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyMessageBegin");
        return _fp.C_VerifyMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_VerifyMessageNext is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyMessageNext");
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessageNext(session, parameter, parameterLen, dataPtr, dataLen, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageVerifyFinal(NativeCULong session)
    {
        if (_fp.C_MessageVerifyFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageVerifyFinal");
        return _fp.C_MessageVerifyFinal(session);
    }

    // ── v3.2 PQC / signature / async / authenticated-wrap wrappers ───────────────

    /// <summary>Wrapper for <c>C_EncapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (_fp.C_EncapsulateKey is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncapsulateKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_EncapsulateKey(session, m, publicKey, t, attributeCount, ctPtr, ctLenPtr, dkPtr);
    }

    /// <summary>Wrapper for <c>C_DecapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (_fp.C_DecapsulateKey is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecapsulateKey");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_DecapsulateKey(session, m, privateKey, t, attributeCount, ctPtr, ciphertextLen, dkPtr);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureInit</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_VerifySignatureInit is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignatureInit");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifySignatureInit(session, m, key, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_VerifySignature</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen)
    {
        if (_fp.C_VerifySignature is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignature");
        fixed (byte* dataPtr = data)
            return _fp.C_VerifySignature(session, dataPtr, dataLen);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        if (_fp.C_VerifySignatureUpdate is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignatureUpdate");
        fixed (byte* partPtr = part)
            return _fp.C_VerifySignatureUpdate(session, partPtr, partLen);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureFinal(NativeCULong session)
    {
        if (_fp.C_VerifySignatureFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignatureFinal");
        return _fp.C_VerifySignatureFinal(session);
    }

    /// <summary>Wrapper for <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        if (_fp.C_GetSessionValidationFlags is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionValidationFlags");
        fixed (NativeCULong* flagsPtr = &flags)
            return _fp.C_GetSessionValidationFlags(session, type, flagsPtr);
    }

    /// <summary>Wrapper for <c>C_AsyncComplete</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncComplete(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result)
    {
        if (_fp.C_AsyncComplete is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_AsyncComplete");
        fixed (byte* fnPtr = functionName)
        fixed (CK_ASYNC_DATA* rPtr = &result)
            return _fp.C_AsyncComplete(session, fnPtr, rPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncComplete</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncComplete => _fp.C_AsyncComplete is not null;

    /// <summary>Wrapper for <c>C_AsyncGetID</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncGetID(NativeCULong session, byte[] functionName, ref NativeCULong id)
    {
        if (_fp.C_AsyncGetID is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_AsyncGetID");
        fixed (byte* fnPtr = functionName)
        fixed (NativeCULong* idPtr = &id)
            return _fp.C_AsyncGetID(session, fnPtr, idPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncGetID</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncGetID => _fp.C_AsyncGetID is not null;

    /// <summary>Wrapper for <c>C_AsyncJoin</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncJoin(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen)
    {
        if (_fp.C_AsyncJoin is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_AsyncJoin");
        fixed (byte* fnPtr = functionName)
        fixed (byte* dataPtr = data)
            return _fp.C_AsyncJoin(session, fnPtr, id, dataPtr, dataLen);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncJoin</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncJoin => _fp.C_AsyncJoin is not null;

    /// <summary>Wrapper for <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[] wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        if (_fp.C_WrapKeyAuthenticated is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_WrapKeyAuthenticated");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* adPtr = associatedData)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKeyAuthenticated(session, m, wrappingKey, key, adPtr, associatedDataLen, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key)
    {
        if (_fp.C_UnwrapKeyAuthenticated is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_UnwrapKeyAuthenticated");
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* adPtr = associatedData)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKeyAuthenticated(session, m, unwrappingKey, wkPtr, wrappedKeyLen, t, attributeCount, adPtr, associatedDataLen, kPtr);
    }

    // ── Windows-layout fptr wrapper methods ──────────────────────────────────
    // These wrap the fptrs in FunctionPointers._fp for blittable _Windows types.
    // Callers check HasC_X_Windows before invoking; the wrapper throws Pkcs11Exception
    // if the fptr is unexpectedly null (defensive only).

    /// <summary>Wrapper for <c>C_CreateObject</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_CreateObject_Windows(NativeCULong session, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong objectId)
    {
        if (_fp.C_CreateObject_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CreateObject_Windows");
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (NativeCULong* idPtr = &objectId)
            return _fp.C_CreateObject_Windows(session, t, count, idPtr);
    }

    /// <summary>Wrapper for <c>C_CopyObject</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_CopyObject_Windows(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong newObjectId)
    {
        if (_fp.C_CopyObject_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CopyObject_Windows");
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (NativeCULong* idPtr = &newObjectId)
            return _fp.C_CopyObject_Windows(session, objectId, t, count, idPtr);
    }

    /// <summary>Wrapper for <c>C_GetAttributeValue</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GetAttributeValue_Windows(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE_Windows[] template, NativeCULong count)
    {
        if (_fp.C_GetAttributeValue_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetAttributeValue_Windows");
        fixed (CK_ATTRIBUTE_Windows* t = template)
            return _fp.C_GetAttributeValue_Windows(session, objectId, t, count);
    }

    /// <summary>Wrapper for <c>C_SetAttributeValue</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_SetAttributeValue_Windows(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE_Windows[] template, NativeCULong count)
    {
        if (_fp.C_SetAttributeValue_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SetAttributeValue_Windows");
        fixed (CK_ATTRIBUTE_Windows* t = template)
            return _fp.C_SetAttributeValue_Windows(session, objectId, t, count);
    }

    /// <summary>Wrapper for <c>C_FindObjectsInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_FindObjectsInit_Windows(NativeCULong session, CK_ATTRIBUTE_Windows[] template, NativeCULong count)
    {
        if (_fp.C_FindObjectsInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_FindObjectsInit_Windows");
        fixed (CK_ATTRIBUTE_Windows* t = template)
            return _fp.C_FindObjectsInit_Windows(session, t, count);
    }

    /// <summary>Wrapper for <c>C_EncryptInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_EncryptInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_EncryptInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_EncryptInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_DecryptInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_DecryptInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_DecryptInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_DecryptInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_DigestInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_DigestInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism)
    {
        if (_fp.C_DigestInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DigestInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_DigestInit_Windows(session, m);
    }

    /// <summary>Wrapper for <c>C_SignInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_SignInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_SignInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_SignInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignRecoverInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_SignRecoverInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_SignRecoverInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SignRecoverInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_SignRecoverInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_VerifyInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_VerifyInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_VerifyInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyRecoverInit</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_VerifyRecoverInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_VerifyRecoverInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyRecoverInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_VerifyRecoverInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_GenerateKey</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GenerateKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong key)
    {
        if (_fp.C_GenerateKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_GenerateKey_Windows(session, m, t, count, kPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKeyPair</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_GenerateKeyPair_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism,
        CK_ATTRIBUTE_Windows[] publicKeyTemplate, NativeCULong publicKeyAttributeCount,
        CK_ATTRIBUTE_Windows[] privateKeyTemplate, NativeCULong privateKeyAttributeCount,
        ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        if (_fp.C_GenerateKeyPair_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GenerateKeyPair_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (CK_ATTRIBUTE_Windows* pub = publicKeyTemplate)
        fixed (CK_ATTRIBUTE_Windows* priv = privateKeyTemplate)
        fixed (NativeCULong* pubK = &publicKey)
        fixed (NativeCULong* privK = &privateKey)
            return _fp.C_GenerateKeyPair_Windows(session, m, pub, publicKeyAttributeCount, priv, privateKeyAttributeCount, pubK, privK);
    }

    /// <summary>Wrapper for <c>C_WrapKey</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_WrapKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        if (_fp.C_WrapKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_WrapKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKey_Windows(session, m, wrappingKey, key, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKey</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_UnwrapKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, ref NativeCULong key)
    {
        if (_fp.C_UnwrapKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_UnwrapKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKey_Windows(session, m, unwrappingKey, wkPtr, wrappedKeyLen, t, attributeCount, kPtr);
    }

    /// <summary>Wrapper for <c>C_DeriveKey</c> with Pack=1 Windows struct layout.</summary>
    public unsafe NativeCULong C_DeriveKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong baseKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, ref NativeCULong key)
    {
        if (_fp.C_DeriveKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DeriveKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_DeriveKey_Windows(session, m, baseKey, t, attributeCount, kPtr);
    }

    /// <summary>Wrapper for <c>C_MessageEncryptInit</c> with Pack=1 Windows struct layout (v3.0).</summary>
    public unsafe NativeCULong C_MessageEncryptInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_MessageEncryptInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageEncryptInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_MessageEncryptInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptInit</c> with Pack=1 Windows struct layout (v3.0).</summary>
    public unsafe NativeCULong C_MessageDecryptInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_MessageDecryptInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageDecryptInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_MessageDecryptInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_MessageSignInit</c> with Pack=1 Windows struct layout (v3.0).</summary>
    public unsafe NativeCULong C_MessageSignInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_MessageSignInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageSignInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_MessageSignInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyInit</c> with Pack=1 Windows struct layout (v3.0).</summary>
    public unsafe NativeCULong C_MessageVerifyInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key)
    {
        if (_fp.C_MessageVerifyInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_MessageVerifyInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism) return _fp.C_MessageVerifyInit_Windows(session, m, key);
    }

    /// <summary>Wrapper for <c>C_EncapsulateKey</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_EncapsulateKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong publicKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (_fp.C_EncapsulateKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_EncapsulateKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_EncapsulateKey_Windows(session, m, publicKey, t, attributeCount, ctPtr, ctLenPtr, dkPtr);
    }

    /// <summary>Wrapper for <c>C_DecapsulateKey</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_DecapsulateKey_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong privateKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (_fp.C_DecapsulateKey_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DecapsulateKey_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_DecapsulateKey_Windows(session, m, privateKey, t, attributeCount, ctPtr, ciphertextLen, dkPtr);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureInit</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_VerifySignatureInit_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen)
    {
        if (_fp.C_VerifySignatureInit_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_VerifySignatureInit_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifySignatureInit_Windows(session, m, key, sigPtr, signatureLen);
    }

    /// <summary>Wrapper for <c>C_AsyncComplete</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_AsyncComplete_Windows(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA_Windows result)
    {
        if (_fp.C_AsyncComplete_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_AsyncComplete_Windows");
        fixed (byte* fnPtr = functionName)
        fixed (CK_ASYNC_DATA_Windows* rPtr = &result)
            return _fp.C_AsyncComplete_Windows(session, fnPtr, rPtr);
    }

    /// <summary>Wrapper for <c>C_WrapKeyAuthenticated</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_WrapKeyAuthenticated_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[] wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        if (_fp.C_WrapKeyAuthenticated_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_WrapKeyAuthenticated_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (byte* adPtr = associatedData)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKeyAuthenticated_Windows(session, m, wrappingKey, key, adPtr, associatedDataLen, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKeyAuthenticated</c> with Pack=1 Windows struct layout (v3.2).</summary>
    public unsafe NativeCULong C_UnwrapKeyAuthenticated_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key)
    {
        if (_fp.C_UnwrapKeyAuthenticated_Windows is null) throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_UnwrapKeyAuthenticated_Windows");
        fixed (CK_MECHANISM_Windows* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE_Windows* t = template)
        fixed (byte* adPtr = associatedData)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKeyAuthenticated_Windows(session, m, unwrappingKey, wkPtr, wrappedKeyLen, t, attributeCount, adPtr, associatedDataLen, kPtr);
    }

    // Has* properties — safe-context null checks for _Windows fptrs (unsafe internally).
    internal unsafe bool HasC_MessageEncryptInit_Windows => _fp.C_MessageEncryptInit_Windows is not null;
    internal unsafe bool HasC_MessageDecryptInit_Windows => _fp.C_MessageDecryptInit_Windows is not null;
    internal unsafe bool HasC_MessageSignInit_Windows => _fp.C_MessageSignInit_Windows is not null;
    internal unsafe bool HasC_MessageVerifyInit_Windows => _fp.C_MessageVerifyInit_Windows is not null;
    internal unsafe bool HasC_EncapsulateKey_Windows => _fp.C_EncapsulateKey_Windows is not null;
    internal unsafe bool HasC_DecapsulateKey_Windows => _fp.C_DecapsulateKey_Windows is not null;
    internal unsafe bool HasC_VerifySignatureInit_Windows => _fp.C_VerifySignatureInit_Windows is not null;
    internal unsafe bool HasC_AsyncComplete_Windows => _fp.C_AsyncComplete_Windows is not null;
    internal unsafe bool HasC_WrapKeyAuthenticated_Windows => _fp.C_WrapKeyAuthenticated_Windows is not null;
    internal unsafe bool HasC_UnwrapKeyAuthenticated_Windows => _fp.C_UnwrapKeyAuthenticated_Windows is not null;
    internal unsafe bool HasC_CreateObject_Windows => _fp.C_CreateObject_Windows is not null;
    internal unsafe bool HasC_CopyObject_Windows => _fp.C_CopyObject_Windows is not null;
    internal unsafe bool HasC_GetAttributeValue_Windows => _fp.C_GetAttributeValue_Windows is not null;
    internal unsafe bool HasC_SetAttributeValue_Windows => _fp.C_SetAttributeValue_Windows is not null;
    internal unsafe bool HasC_FindObjectsInit_Windows => _fp.C_FindObjectsInit_Windows is not null;
    internal unsafe bool HasC_EncryptInit_Windows => _fp.C_EncryptInit_Windows is not null;
    internal unsafe bool HasC_DecryptInit_Windows => _fp.C_DecryptInit_Windows is not null;
    internal unsafe bool HasC_DigestInit_Windows => _fp.C_DigestInit_Windows is not null;
    internal unsafe bool HasC_SignInit_Windows => _fp.C_SignInit_Windows is not null;
    internal unsafe bool HasC_SignRecoverInit_Windows => _fp.C_SignRecoverInit_Windows is not null;
    internal unsafe bool HasC_VerifyInit_Windows => _fp.C_VerifyInit_Windows is not null;
    internal unsafe bool HasC_VerifyRecoverInit_Windows => _fp.C_VerifyRecoverInit_Windows is not null;
    internal unsafe bool HasC_GenerateKey_Windows => _fp.C_GenerateKey_Windows is not null;
    internal unsafe bool HasC_GenerateKeyPair_Windows => _fp.C_GenerateKeyPair_Windows is not null;
    internal unsafe bool HasC_WrapKey_Windows => _fp.C_WrapKey_Windows is not null;
    internal unsafe bool HasC_UnwrapKey_Windows => _fp.C_UnwrapKey_Windows is not null;
    internal unsafe bool HasC_DeriveKey_Windows => _fp.C_DeriveKey_Windows is not null;

    /// <summary>
    /// Initializes a new instance of <see cref="Delegates"/>. Function pointers are
    /// acquired via <c>C_GetFunctionList</c> against the dynamically loaded library
    /// when <paramref name="libraryHandle"/> is non-zero, or against the
    /// statically-linked PKCS#11 symbols otherwise (iOS-style "__Internal" link).
    /// </summary>
    /// <param name="libraryHandle">Handle to the dynamically loaded PKCS#11 library,
    /// or <see cref="IntPtr.Zero"/> for a statically-linked library.</param>
    internal Delegates(IntPtr libraryHandle)
    {
        if (libraryHandle != IntPtr.Zero)
        {
            InitializeWithGetFunctionList(libraryHandle);
            // Best-effort load of v3.0 functions via direct symbol lookup. The full
            // C_GetInterface-based loader path lives in Pkcs11Library / bucket E.
            TryLoadV30Symbols(libraryHandle);
        }
        else
        {
            InitializeWithGetFunctionList();
        }
    }

    /// <summary>
    /// Best-effort: bind v3.0 function pointers. Preferred path is C_GetInterface
    /// (v3.0 §5.4.5) which yields a typed CK_FUNCTION_LIST_3_0 carrying every v2.40
    /// pointer plus the v3.0 additions. Fallback path: per-symbol NativeLibrary lookup
    /// against the dynamically loaded library — handles v2.40 tokens (delegates stay
    /// <see langword="null"/>) and v3.0 tokens that export individual symbols but
    /// don't publish the interface table.
    /// </summary>
    private void TryLoadV30Symbols(IntPtr libraryHandle)
    {
        // Preferred: ask the library for its v3.0 interface table.
        if (TryLoadFromGetInterface(libraryHandle))
            return;

        // Fallback: per-symbol lookup. Works for libraries that export the v3.0
        // functions as plain symbols even though they don't expose C_GetInterface.
        if (NativeLibrary.TryGetExport(libraryHandle, "C_LoginUser", out IntPtr loginUserPtr) && loginUserPtr != IntPtr.Zero)
            unsafe { _fp.C_LoginUser = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)loginUserPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_SessionCancel", out IntPtr sessionCancelPtr) && sessionCancelPtr != IntPtr.Zero)
            unsafe { _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)sessionCancelPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageEncryptInit", out IntPtr msgEncInitPtr) && msgEncInitPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageEncryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)msgEncInitPtr; }
            unsafe { _fp.C_MessageEncryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)msgEncInitPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_EncryptMessage", out IntPtr encMsgPtr) && encMsgPtr != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)encMsgPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_EncryptMessageBegin", out IntPtr encMsgBeginPtr) && encMsgBeginPtr != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)encMsgBeginPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_EncryptMessageNext", out IntPtr encMsgNextPtr) && encMsgNextPtr != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)encMsgNextPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageEncryptFinal", out IntPtr msgEncFinalPtr) && msgEncFinalPtr != IntPtr.Zero)
            unsafe { _fp.C_MessageEncryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)msgEncFinalPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageDecryptInit", out IntPtr msgDecInitPtr) && msgDecInitPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageDecryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)msgDecInitPtr; }
            unsafe { _fp.C_MessageDecryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)msgDecInitPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_DecryptMessage", out IntPtr decMsgPtr) && decMsgPtr != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)decMsgPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_DecryptMessageBegin", out IntPtr decMsgBeginPtr) && decMsgBeginPtr != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)decMsgBeginPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_DecryptMessageNext", out IntPtr decMsgNextPtr) && decMsgNextPtr != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)decMsgNextPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageDecryptFinal", out IntPtr msgDecFinalPtr) && msgDecFinalPtr != IntPtr.Zero)
            unsafe { _fp.C_MessageDecryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)msgDecFinalPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageSignInit", out IntPtr msgSignInitPtr) && msgSignInitPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageSignInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)msgSignInitPtr; }
            unsafe { _fp.C_MessageSignInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)msgSignInitPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_SignMessage", out IntPtr signMsgPtr) && signMsgPtr != IntPtr.Zero)
            unsafe { _fp.C_SignMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)signMsgPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_SignMessageBegin", out IntPtr signMsgBeginPtr) && signMsgBeginPtr != IntPtr.Zero)
            unsafe { _fp.C_SignMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)signMsgBeginPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_SignMessageNext", out IntPtr signMsgNextPtr) && signMsgNextPtr != IntPtr.Zero)
            unsafe { _fp.C_SignMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)signMsgNextPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageSignFinal", out IntPtr msgSignFinalPtr) && msgSignFinalPtr != IntPtr.Zero)
            unsafe { _fp.C_MessageSignFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)msgSignFinalPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageVerifyInit", out IntPtr msgVerifyInitPtr) && msgVerifyInitPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageVerifyInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)msgVerifyInitPtr; }
            unsafe { _fp.C_MessageVerifyInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)msgVerifyInitPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifyMessage", out IntPtr verMsgPtr) && verMsgPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)verMsgPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifyMessageBegin", out IntPtr verMsgBeginPtr) && verMsgBeginPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)verMsgBeginPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifyMessageNext", out IntPtr verMsgNextPtr) && verMsgNextPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)verMsgNextPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_MessageVerifyFinal", out IntPtr msgVerifyFinalPtr) && msgVerifyFinalPtr != IntPtr.Zero)
            unsafe { _fp.C_MessageVerifyFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)msgVerifyFinalPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_EncapsulateKey", out IntPtr encapPtr) && encapPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_EncapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)encapPtr; }
            unsafe { _fp.C_EncapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)encapPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_DecapsulateKey", out IntPtr decapPtr) && decapPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_DecapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)decapPtr; }
            unsafe { _fp.C_DecapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)decapPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifySignatureInit", out IntPtr vsiPtr) && vsiPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_VerifySignatureInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, NativeCULong>)vsiPtr; }
            unsafe { _fp.C_VerifySignatureInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong>)vsiPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifySignature", out IntPtr vsPtr) && vsPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifySignature = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)vsPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifySignatureUpdate", out IntPtr vsuPtr) && vsuPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifySignatureUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)vsuPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_VerifySignatureFinal", out IntPtr vsfPtr) && vsfPtr != IntPtr.Zero)
            unsafe { _fp.C_VerifySignatureFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)vsfPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_GetSessionValidationFlags", out IntPtr gsvfPtr) && gsvfPtr != IntPtr.Zero)
            unsafe { _fp.C_GetSessionValidationFlags = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)gsvfPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_AsyncComplete", out IntPtr asyncCompletePtr) && asyncCompletePtr != IntPtr.Zero)
        {
            unsafe { _fp.C_AsyncComplete = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA*, NativeCULong>)asyncCompletePtr; }
            unsafe { _fp.C_AsyncComplete_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA_Windows*, NativeCULong>)asyncCompletePtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_AsyncGetID", out IntPtr asyncGetIdPtr) && asyncGetIdPtr != IntPtr.Zero)
            unsafe { _fp.C_AsyncGetID = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)asyncGetIdPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_AsyncJoin", out IntPtr asyncJoinPtr) && asyncJoinPtr != IntPtr.Zero)
            unsafe { _fp.C_AsyncJoin = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)asyncJoinPtr; }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_WrapKeyAuthenticated", out IntPtr wkaPtr) && wkaPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_WrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)wkaPtr; }
            unsafe { _fp.C_WrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)wkaPtr; }
        }
        if (NativeLibrary.TryGetExport(libraryHandle, "C_UnwrapKeyAuthenticated", out IntPtr uwkaPtr) && uwkaPtr != IntPtr.Zero)
        {
            unsafe { _fp.C_UnwrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)uwkaPtr; }
            unsafe { _fp.C_UnwrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)uwkaPtr; }
        }
    }

    /// <summary>
    /// Tries the preferred v3.0 loader path: call C_GetInterface to obtain the default
    /// "PKCS 11" interface, then read its function table as <see cref="CK_FUNCTION_LIST_3_0"/>
    /// and bind every v3.0 delegate from the table. Returns true on success, false if
    /// C_GetInterface is unavailable / fails / returns a non-3.x version, leaving the
    /// caller to use the per-symbol fallback.
    /// </summary>
    private bool TryLoadFromGetInterface(IntPtr libraryHandle)
    {
        if (!NativeLibrary.TryGetExport(libraryHandle, "C_GetInterface", out IntPtr getInterfaceRawPtr) || getInterfaceRawPtr == IntPtr.Zero)
            return false;
        unsafe { _fp.C_GetInterface = (delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)getInterfaceRawPtr; }

        // Request the default interface: null name, null version, flags = 0.
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

        if (rv.ToCKRChecked() != CKR.CKR_OK || interfacePtr == IntPtr.Zero)
            return false;

        CK_INTERFACE iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        if (iface.FunctionList == IntPtr.Zero)
            return false;

        // The function-list pointer can be either CK_FUNCTION_LIST (v2.40) or
        // CK_FUNCTION_LIST_3_0 (v3.0+). The CK_VERSION header at offset 0 distinguishes
        // them. Read just the version first to decide.
        CK_VERSION version = UnmanagedMemory.Read<CK_VERSION>(iface.FunctionList);
        if (version.Major < 3) return false;

        CK_FUNCTION_LIST_3_0 v30 = UnmanagedMemory.Read<CK_FUNCTION_LIST_3_0>(iface.FunctionList);

        if (v30.C_LoginUser != IntPtr.Zero)
            unsafe { _fp.C_LoginUser = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)v30.C_LoginUser; }
        if (v30.C_SessionCancel != IntPtr.Zero)
            unsafe { _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)v30.C_SessionCancel; }

        if (v30.C_MessageEncryptInit != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageEncryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)v30.C_MessageEncryptInit; }
            unsafe { _fp.C_MessageEncryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)v30.C_MessageEncryptInit; }
        }
        if (v30.C_EncryptMessage != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v30.C_EncryptMessage; }
        if (v30.C_EncryptMessageBegin != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)v30.C_EncryptMessageBegin; }
        if (v30.C_EncryptMessageNext != IntPtr.Zero)
            unsafe { _fp.C_EncryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)v30.C_EncryptMessageNext; }
        if (v30.C_MessageEncryptFinal != IntPtr.Zero)
            unsafe { _fp.C_MessageEncryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)v30.C_MessageEncryptFinal; }

        if (v30.C_MessageDecryptInit != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageDecryptInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)v30.C_MessageDecryptInit; }
            unsafe { _fp.C_MessageDecryptInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)v30.C_MessageDecryptInit; }
        }
        if (v30.C_DecryptMessage != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v30.C_DecryptMessage; }
        if (v30.C_DecryptMessageBegin != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)v30.C_DecryptMessageBegin; }
        if (v30.C_DecryptMessageNext != IntPtr.Zero)
            unsafe { _fp.C_DecryptMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)v30.C_DecryptMessageNext; }
        if (v30.C_MessageDecryptFinal != IntPtr.Zero)
            unsafe { _fp.C_MessageDecryptFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)v30.C_MessageDecryptFinal; }

        if (v30.C_MessageSignInit != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageSignInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)v30.C_MessageSignInit; }
            unsafe { _fp.C_MessageSignInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)v30.C_MessageSignInit; }
        }
        if (v30.C_SignMessage != IntPtr.Zero)
            unsafe { _fp.C_SignMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v30.C_SignMessage; }
        if (v30.C_SignMessageBegin != IntPtr.Zero)
            unsafe { _fp.C_SignMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)v30.C_SignMessageBegin; }
        if (v30.C_SignMessageNext != IntPtr.Zero)
            unsafe { _fp.C_SignMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v30.C_SignMessageNext; }
        if (v30.C_MessageSignFinal != IntPtr.Zero)
            unsafe { _fp.C_MessageSignFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)v30.C_MessageSignFinal; }

        if (v30.C_MessageVerifyInit != IntPtr.Zero)
        {
            unsafe { _fp.C_MessageVerifyInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong>)v30.C_MessageVerifyInit; }
            unsafe { _fp.C_MessageVerifyInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong>)v30.C_MessageVerifyInit; }
        }
        if (v30.C_VerifyMessage != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessage = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)v30.C_VerifyMessage; }
        if (v30.C_VerifyMessageBegin != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessageBegin = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)v30.C_VerifyMessageBegin; }
        if (v30.C_VerifyMessageNext != IntPtr.Zero)
            unsafe { _fp.C_VerifyMessageNext = (delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)v30.C_VerifyMessageNext; }
        if (v30.C_MessageVerifyFinal != IntPtr.Zero)
            unsafe { _fp.C_MessageVerifyFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)v30.C_MessageVerifyFinal; }

        // v3.2 token: re-read the function table as CK_FUNCTION_LIST_3_2 and bind
        // the 12 v3.2 additions on top of the v3.0 bindings.
        if (version.Minor >= 2)
        {
            CK_FUNCTION_LIST_3_2 v32 = UnmanagedMemory.Read<CK_FUNCTION_LIST_3_2>(iface.FunctionList);

            if (v32.C_EncapsulateKey != IntPtr.Zero)
            {
                unsafe { _fp.C_EncapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)v32.C_EncapsulateKey; }
                unsafe { _fp.C_EncapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)v32.C_EncapsulateKey; }
            }
            if (v32.C_DecapsulateKey != IntPtr.Zero)
            {
                unsafe { _fp.C_DecapsulateKey = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)v32.C_DecapsulateKey; }
                unsafe { _fp.C_DecapsulateKey_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)v32.C_DecapsulateKey; }
            }
            if (v32.C_VerifySignatureInit != IntPtr.Zero)
            {
                unsafe { _fp.C_VerifySignatureInit = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, NativeCULong>)v32.C_VerifySignatureInit; }
                unsafe { _fp.C_VerifySignatureInit_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong>)v32.C_VerifySignatureInit; }
            }
            if (v32.C_VerifySignature != IntPtr.Zero)
                unsafe { _fp.C_VerifySignature = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)v32.C_VerifySignature; }
            if (v32.C_VerifySignatureUpdate != IntPtr.Zero)
                unsafe { _fp.C_VerifySignatureUpdate = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)v32.C_VerifySignatureUpdate; }
            if (v32.C_VerifySignatureFinal != IntPtr.Zero)
                unsafe { _fp.C_VerifySignatureFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)v32.C_VerifySignatureFinal; }
            if (v32.C_GetSessionValidationFlags != IntPtr.Zero)
                unsafe { _fp.C_GetSessionValidationFlags = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)v32.C_GetSessionValidationFlags; }
            if (v32.C_AsyncComplete != IntPtr.Zero)
            {
                unsafe { _fp.C_AsyncComplete = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA*, NativeCULong>)v32.C_AsyncComplete; }
                unsafe { _fp.C_AsyncComplete_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA_Windows*, NativeCULong>)v32.C_AsyncComplete; }
            }
            if (v32.C_AsyncGetID != IntPtr.Zero)
                unsafe { _fp.C_AsyncGetID = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)v32.C_AsyncGetID; }
            if (v32.C_AsyncJoin != IntPtr.Zero)
                unsafe { _fp.C_AsyncJoin = (delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)v32.C_AsyncJoin; }
            if (v32.C_WrapKeyAuthenticated != IntPtr.Zero)
            {
                unsafe { _fp.C_WrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v32.C_WrapKeyAuthenticated; }
                unsafe { _fp.C_WrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)v32.C_WrapKeyAuthenticated; }
            }
            if (v32.C_UnwrapKeyAuthenticated != IntPtr.Zero)
            {
                unsafe { _fp.C_UnwrapKeyAuthenticated = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)v32.C_UnwrapKeyAuthenticated; }
                unsafe { _fp.C_UnwrapKeyAuthenticated_Windows = (delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)v32.C_UnwrapKeyAuthenticated; }
            }
        }

        return true;
    }

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
    /// </summary>
    /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
    private unsafe void InitializeWithGetFunctionList(IntPtr libraryHandle)
    {
        IntPtr getFunctionListPtr = NativeLibrary.GetExport(libraryHandle, "C_GetFunctionList");
        var getFunctionList = (delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)getFunctionListPtr;

        IntPtr functionList = IntPtr.Zero;

        CKR returnValue = getFunctionList(&functionList).ToCKRChecked();
        Pkcs11Exception.ThrowIfError(returnValue, "C_GetFunctionList");
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        CK_FUNCTION_LIST funcList = UnmanagedMemory.Read<CK_FUNCTION_LIST>(functionList);
        Initialize(funcList);
    }

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the statically linked PKCS#11 library
    /// </summary>
    private void InitializeWithGetFunctionList()
    {
        CKR returnValue = NativeMethods.C_GetFunctionList(out IntPtr functionList).ToCKRChecked();
        Pkcs11Exception.ThrowIfError(returnValue, "C_GetFunctionList");
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