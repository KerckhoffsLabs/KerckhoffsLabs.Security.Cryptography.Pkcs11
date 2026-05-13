using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitializeDelegate(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FinalizeDelegate(IntPtr reserved);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetInfoDelegate(ref CK_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetFunctionListDelegate(out IntPtr functionList);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSlotListDelegate([MarshalAs(UnmanagedType.U1)] bool tokenPresent, [In, Out] NativeCULong[] slotList, ref NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSlotInfoDelegate(NativeCULong slotId, ref CK_SLOT_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetTokenInfoDelegate(NativeCULong slotId, ref CK_TOKEN_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetMechanismListDelegate(NativeCULong slotId, [In, Out] NativeCULong[] mechanismList, ref NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetMechanismInfoDelegate(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitTokenDelegate(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitPINDelegate(NativeCULong session, byte[] pin, NativeCULong pinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetPINDelegate(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_OpenSessionDelegate(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CloseSessionDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CloseAllSessionsDelegate(NativeCULong slotId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSessionInfoDelegate(NativeCULong session, ref CK_SESSION_INFO info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetOperationStateDelegate(NativeCULong session, [In, Out] byte[] operationState, ref NativeCULong operationStateLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetOperationStateDelegate(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_LoginDelegate(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_LogoutDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CreateObjectDelegate(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong objectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CopyObjectDelegate(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong newObjectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DestroyObjectDelegate(NativeCULong session, NativeCULong objectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetObjectSizeDelegate(NativeCULong session, NativeCULong objectId, ref NativeCULong size);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetAttributeValueDelegate(NativeCULong session, NativeCULong objectId, [In, Out] CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetAttributeValueDelegate(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsInitDelegate(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsDelegate(NativeCULong session, [In, Out] NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsFinalDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptDelegate(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] encryptedData, ref NativeCULong encryptedDataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptFinalDelegate(NativeCULong session, [In, Out] byte[] lastEncryptedPart, ref NativeCULong lastEncryptedPartLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptDelegate(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, [In, Out] byte[] data, ref NativeCULong dataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptUpdateDelegate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptFinalDelegate(NativeCULong session, [In, Out] byte[] lastPart, ref NativeCULong lastPartLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestDelegate(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] digest, ref NativeCULong digestLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestKeyDelegate(NativeCULong session, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestFinalDelegate(NativeCULong session, [In, Out] byte[] digest, ref NativeCULong digestLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignDelegate(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] signature, ref NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignFinalDelegate(NativeCULong session, [In, Out] byte[] signature, ref NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignRecoverInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignRecoverDelegate(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] signature, ref NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyDelegate(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyFinalDelegate(NativeCULong session, byte[] signature, NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyRecoverInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyRecoverDelegate(NativeCULong session, byte[] signature, NativeCULong signatureLen, [In, Out] byte[] data, ref NativeCULong dataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestEncryptUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptDigestUpdateDelegate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignEncryptUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptVerifyUpdateDelegate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateKeyPairDelegate(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[] privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_WrapKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, [In, Out] byte[] wrappedKey, ref NativeCULong wrappedKeyLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_UnwrapKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DeriveKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SeedRandomDelegate(NativeCULong session, byte[] seed, NativeCULong seedLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateRandomDelegate(NativeCULong session, [In, Out] byte[] randomData, NativeCULong randomLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetFunctionStatusDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CancelFunctionDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_WaitForSlotEventDelegate(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);

/// <summary>
/// Holds delegates for all PKCS#11 functions
/// </summary>
internal partial class Delegates
{
    /// <summary>
    /// Definition of unmanaged methods (used on iOS)
    /// </summary>
    private static partial class NativeMethods
    {
        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Initialize(IntPtr pInitArgs);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Finalize(IntPtr reserved);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetInfo(ref CK_INFO info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetFunctionList(out IntPtr functionList);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetSlotList([MarshalAs(UnmanagedType.U1)] bool tokenPresent, [In, Out] NativeCULong[] slotList, ref NativeCULong count);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetMechanismList(NativeCULong slotId, [In, Out] NativeCULong[] mechanismList, ref NativeCULong count);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_CloseSession(NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_CloseAllSessions(NativeCULong slotId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetOperationState(NativeCULong session, [In, Out] byte[] operationState, ref NativeCULong operationStateLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Login(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Logout(NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong objectId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong newObjectId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetAttributeValue(NativeCULong session, NativeCULong objectId, [In, Out] CK_ATTRIBUTE[] template, NativeCULong count);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_FindObjects(NativeCULong session, [In, Out] NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_FindObjectsFinal(NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] encryptedData, ref NativeCULong encryptedDataLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_EncryptFinal(NativeCULong session, [In, Out] byte[] lastEncryptedPart, ref NativeCULong lastEncryptedPartLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, [In, Out] byte[] data, ref NativeCULong dataLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DecryptFinal(NativeCULong session, [In, Out] byte[] lastPart, ref NativeCULong lastPartLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] digest, ref NativeCULong digestLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DigestKey(NativeCULong session, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DigestFinal(NativeCULong session, [In, Out] byte[] digest, ref NativeCULong digestLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] signature, ref NativeCULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignFinal(NativeCULong session, [In, Out] byte[] signature, ref NativeCULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, [In, Out] byte[] signature, ref NativeCULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, [In, Out] byte[] data, ref NativeCULong dataLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, [In, Out] byte[] encryptedPart, ref NativeCULong encryptedPartLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, [In, Out] byte[] part, ref NativeCULong partLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[] privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, [In, Out] byte[] wrappedKey, ref NativeCULong wrappedKeyLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GenerateRandom(NativeCULong session, [In, Out] byte[] randomData, NativeCULong randomLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetFunctionStatus(NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_CancelFunction(NativeCULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);
    }

    /// <summary>
    /// Delegate for C_Initialize
    /// </summary>
    internal C_InitializeDelegate? C_Initialize = null;

    /// <summary>
    /// Delegate for C_Finalize
    /// </summary>
    internal C_FinalizeDelegate? C_Finalize = null;

    /// <summary>
    /// Delegate for C_GetInfo
    /// </summary>
    internal C_GetInfoDelegate? C_GetInfo = null;

    /// <summary>
    /// Delegate for C_GetFunctionList
    /// </summary>
    internal C_GetFunctionListDelegate? C_GetFunctionList = null;

    /// <summary>
    /// Delegate for C_GetSlotList
    /// </summary>
    internal C_GetSlotListDelegate? C_GetSlotList = null;

    /// <summary>
    /// Delegate for C_GetSlotInfo
    /// </summary>
    internal C_GetSlotInfoDelegate? C_GetSlotInfo = null;

    /// <summary>
    /// Delegate for C_GetTokenInfo
    /// </summary>
    internal C_GetTokenInfoDelegate? C_GetTokenInfo = null;

    /// <summary>
    /// Delegate for C_GetMechanismList
    /// </summary>
    internal C_GetMechanismListDelegate? C_GetMechanismList = null;

    /// <summary>
    /// Delegate for C_GetMechanismInfo
    /// </summary>
    internal C_GetMechanismInfoDelegate? C_GetMechanismInfo = null;

    /// <summary>
    /// Delegate for C_InitToken
    /// </summary>
    internal C_InitTokenDelegate? C_InitToken = null;

    /// <summary>
    /// Delegate for C_InitPIN
    /// </summary>
    internal C_InitPINDelegate? C_InitPIN = null;

    /// <summary>
    /// Delegate for C_SetPIN
    /// </summary>
    internal C_SetPINDelegate? C_SetPIN = null;

    /// <summary>
    /// Delegate for C_OpenSession
    /// </summary>
    internal C_OpenSessionDelegate? C_OpenSession = null;

    /// <summary>
    /// Delegate for C_CloseSession
    /// </summary>
    internal C_CloseSessionDelegate? C_CloseSession = null;

    /// <summary>
    /// Delegate for C_CloseAllSessions
    /// </summary>
    internal C_CloseAllSessionsDelegate? C_CloseAllSessions = null;

    /// <summary>
    /// Delegate for C_GetSessionInfo
    /// </summary>
    internal C_GetSessionInfoDelegate? C_GetSessionInfo = null;

    /// <summary>
    /// Delegate for C_GetOperationState
    /// </summary>
    internal C_GetOperationStateDelegate? C_GetOperationState = null;

    /// <summary>
    /// Delegate for C_SetOperationState
    /// </summary>
    internal C_SetOperationStateDelegate? C_SetOperationState = null;

    /// <summary>
    /// Delegate for C_Login
    /// </summary>
    internal C_LoginDelegate? C_Login = null;

    /// <summary>
    /// Delegate for C_Logout
    /// </summary>
    internal C_LogoutDelegate? C_Logout = null;

    /// <summary>
    /// Delegate for C_CreateObject
    /// </summary>
    internal C_CreateObjectDelegate? C_CreateObject = null;

    /// <summary>
    /// Delegate for C_CopyObject
    /// </summary>
    internal C_CopyObjectDelegate? C_CopyObject = null;

    /// <summary>
    /// Delegate for C_DestroyObject
    /// </summary>
    internal C_DestroyObjectDelegate? C_DestroyObject = null;

    /// <summary>
    /// Delegate for C_GetObjectSize
    /// </summary>
    internal C_GetObjectSizeDelegate? C_GetObjectSize = null;

    /// <summary>
    /// Delegate for C_GetAttributeValue
    /// </summary>
    internal C_GetAttributeValueDelegate? C_GetAttributeValue = null;

    /// <summary>
    /// Delegate for C_SetAttributeValue
    /// </summary>
    internal C_SetAttributeValueDelegate? C_SetAttributeValue = null;

    /// <summary>
    /// Delegate for C_FindObjectsInit
    /// </summary>
    internal C_FindObjectsInitDelegate? C_FindObjectsInit = null;

    /// <summary>
    /// Delegate for C_FindObjects
    /// </summary>
    internal C_FindObjectsDelegate? C_FindObjects = null;

    /// <summary>
    /// Delegate for C_FindObjectsFinal
    /// </summary>
    internal C_FindObjectsFinalDelegate? C_FindObjectsFinal = null;

    /// <summary>
    /// Delegate for C_EncryptInit
    /// </summary>
    internal C_EncryptInitDelegate? C_EncryptInit = null;

    /// <summary>
    /// Delegate for C_Encrypt
    /// </summary>
    internal C_EncryptDelegate? C_Encrypt = null;

    /// <summary>
    /// Delegate for C_EncryptUpdate
    /// </summary>
    internal C_EncryptUpdateDelegate? C_EncryptUpdate = null;

    /// <summary>
    /// Delegate for C_EncryptFinal
    /// </summary>
    internal C_EncryptFinalDelegate? C_EncryptFinal = null;

    /// <summary>
    /// Delegate for C_DecryptInit
    /// </summary>
    internal C_DecryptInitDelegate? C_DecryptInit = null;

    /// <summary>
    /// Delegate for C_Decrypt
    /// </summary>
    internal C_DecryptDelegate? C_Decrypt = null;

    /// <summary>
    /// Delegate for C_DecryptUpdate
    /// </summary>
    internal C_DecryptUpdateDelegate? C_DecryptUpdate = null;

    /// <summary>
    /// Delegate for C_DecryptFinal
    /// </summary>
    internal C_DecryptFinalDelegate? C_DecryptFinal = null;

    /// <summary>
    /// Delegate for C_DigestInit
    /// </summary>
    internal C_DigestInitDelegate? C_DigestInit = null;

    /// <summary>
    /// Delegate for C_Digest
    /// </summary>
    internal C_DigestDelegate? C_Digest = null;

    /// <summary>
    /// Delegate for C_DigestUpdate
    /// </summary>
    internal C_DigestUpdateDelegate? C_DigestUpdate = null;

    /// <summary>
    /// Delegate for C_DigestKey
    /// </summary>
    internal C_DigestKeyDelegate? C_DigestKey = null;

    /// <summary>
    /// Delegate for C_DigestFinal
    /// </summary>
    internal C_DigestFinalDelegate? C_DigestFinal = null;

    /// <summary>
    /// Delegate for C_SignInit
    /// </summary>
    internal C_SignInitDelegate? C_SignInit = null;

    /// <summary>
    /// Delegate for C_Sign
    /// </summary>
    internal C_SignDelegate? C_Sign = null;

    /// <summary>
    /// Delegate for C_SignUpdate
    /// </summary>
    internal C_SignUpdateDelegate? C_SignUpdate = null;

    /// <summary>
    /// Delegate for C_SignFinal
    /// </summary>
    internal C_SignFinalDelegate? C_SignFinal = null;

    /// <summary>
    /// Delegate for C_SignRecoverInit
    /// </summary>
    internal C_SignRecoverInitDelegate? C_SignRecoverInit = null;

    /// <summary>
    /// Delegate for C_SignRecover
    /// </summary>
    internal C_SignRecoverDelegate? C_SignRecover = null;

    /// <summary>
    /// Delegate for C_VerifyInit
    /// </summary>
    internal C_VerifyInitDelegate? C_VerifyInit = null;

    /// <summary>
    /// Delegate for C_Verify
    /// </summary>
    internal C_VerifyDelegate? C_Verify = null;

    /// <summary>
    /// Delegate for C_VerifyUpdate
    /// </summary>
    internal C_VerifyUpdateDelegate? C_VerifyUpdate = null;

    /// <summary>
    /// Delegate for C_VerifyFinal
    /// </summary>
    internal C_VerifyFinalDelegate? C_VerifyFinal = null;

    /// <summary>
    /// Delegate for C_VerifyRecoverInit
    /// </summary>
    internal C_VerifyRecoverInitDelegate? C_VerifyRecoverInit = null;

    /// <summary>
    /// Delegate for C_VerifyRecover
    /// </summary>
    internal C_VerifyRecoverDelegate? C_VerifyRecover = null;

    /// <summary>
    /// Delegate for C_DigestEncryptUpdate
    /// </summary>
    internal C_DigestEncryptUpdateDelegate? C_DigestEncryptUpdate = null;

    /// <summary>
    /// Delegate for C_DecryptDigestUpdate
    /// </summary>
    internal C_DecryptDigestUpdateDelegate? C_DecryptDigestUpdate = null;

    /// <summary>
    /// Delegate for C_SignEncryptUpdate
    /// </summary>
    internal C_SignEncryptUpdateDelegate? C_SignEncryptUpdate = null;

    /// <summary>
    /// Delegate for C_DecryptVerifyUpdate
    /// </summary>
    internal C_DecryptVerifyUpdateDelegate? C_DecryptVerifyUpdate = null;

    /// <summary>
    /// Delegate for C_GenerateKey
    /// </summary>
    internal C_GenerateKeyDelegate? C_GenerateKey = null;

    /// <summary>
    /// Delegate for C_GenerateKeyPair
    /// </summary>
    internal C_GenerateKeyPairDelegate? C_GenerateKeyPair = null;

    /// <summary>
    /// Delegate for C_WrapKey
    /// </summary>
    internal C_WrapKeyDelegate? C_WrapKey = null;

    /// <summary>
    /// Delegate for C_UnwrapKey
    /// </summary>
    internal C_UnwrapKeyDelegate? C_UnwrapKey = null;

    /// <summary>
    /// Delegate for C_DeriveKey
    /// </summary>
    internal C_DeriveKeyDelegate? C_DeriveKey = null;

    /// <summary>
    /// Delegate for C_SeedRandom
    /// </summary>
    internal C_SeedRandomDelegate? C_SeedRandom = null;

    /// <summary>
    /// Delegate for C_GenerateRandom
    /// </summary>
    internal C_GenerateRandomDelegate? C_GenerateRandom = null;

    /// <summary>
    /// Delegate for C_GetFunctionStatus
    /// </summary>
    internal C_GetFunctionStatusDelegate? C_GetFunctionStatus = null;

    /// <summary>
    /// Delegate for C_CancelFunction
    /// </summary>
    internal C_CancelFunctionDelegate? C_CancelFunction = null;

    /// <summary>
    /// Delegate for C_WaitForSlotEvent
    /// </summary>
    internal C_WaitForSlotEventDelegate? C_WaitForSlotEvent = null;

    /// <summary>
    /// Initializes new instance of Delegates class
    /// </summary>
    /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
    /// <param name="useGetFunctionList">Flag indicating whether cryptoki function pointers should be acquired via C_GetFunctionList (true) or via platform native function (false)</param>
    internal Delegates(IntPtr libraryHandle, bool useGetFunctionList)
    {
        if (useGetFunctionList)
        {
            if (libraryHandle != IntPtr.Zero)
            {
                InitializeWithGetFunctionList(libraryHandle);
            }
            else
            {
                InitializeWithGetFunctionList();
            }
        }
        else
        {
            if (libraryHandle != IntPtr.Zero)
            {
                InitializeWithoutGetFunctionList(libraryHandle);
            }
            else
            {
                InitializeWithoutGetFunctionList();
            }
        }
    }

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
    /// </summary>
    /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
    private void InitializeWithGetFunctionList(IntPtr libraryHandle)
    {
        IntPtr getFunctionListPtr = NativeLibrary.GetExport(libraryHandle, "C_GetFunctionList");
        C_GetFunctionListDelegate getFunctionList = Marshal.GetDelegateForFunctionPointer<C_GetFunctionListDelegate>(getFunctionListPtr);

        IntPtr functionList = IntPtr.Zero;

        CKR returnValue = getFunctionList(out functionList).ToCKRChecked();
        Pkcs11Exception.ThrowIfError(returnValue, "C_GetFunctionList");
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        CK_FUNCTION_LIST funcList = (CK_FUNCTION_LIST)UnmanagedMemory.Read(functionList, typeof(CK_FUNCTION_LIST));
        Initialize(funcList);
    }

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the statically linked PKCS#11 library
    /// </summary>
    private void InitializeWithGetFunctionList()
    {
        IntPtr functionList = IntPtr.Zero;

        CKR returnValue = NativeMethods.C_GetFunctionList(out functionList).ToCKRChecked();
        Pkcs11Exception.ThrowIfError(returnValue, "C_GetFunctionList");
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        CK_FUNCTION_LIST funcList = (CK_FUNCTION_LIST)UnmanagedMemory.Read(functionList, typeof(CK_FUNCTION_LIST));
        Initialize(funcList);
    }

    /// <summary>
    /// Get delegates without C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
    /// </summary>
    /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
    private void InitializeWithoutGetFunctionList(IntPtr libraryHandle)
    {
        CK_FUNCTION_LIST funcList = new()
        {
            C_Initialize = NativeLibrary.GetExport(libraryHandle, "C_Initialize"),
            C_Finalize = NativeLibrary.GetExport(libraryHandle, "C_Finalize"),
            C_GetInfo = NativeLibrary.GetExport(libraryHandle, "C_GetInfo"),
            C_GetFunctionList = NativeLibrary.GetExport(libraryHandle, "C_GetFunctionList"),
            C_GetSlotList = NativeLibrary.GetExport(libraryHandle, "C_GetSlotList"),
            C_GetSlotInfo = NativeLibrary.GetExport(libraryHandle, "C_GetSlotInfo"),
            C_GetTokenInfo = NativeLibrary.GetExport(libraryHandle, "C_GetTokenInfo"),
            C_GetMechanismList = NativeLibrary.GetExport(libraryHandle, "C_GetMechanismList"),
            C_GetMechanismInfo = NativeLibrary.GetExport(libraryHandle, "C_GetMechanismInfo"),
            C_InitToken = NativeLibrary.GetExport(libraryHandle, "C_InitToken"),
            C_InitPIN = NativeLibrary.GetExport(libraryHandle, "C_InitPIN"),
            C_SetPIN = NativeLibrary.GetExport(libraryHandle, "C_SetPIN"),
            C_OpenSession = NativeLibrary.GetExport(libraryHandle, "C_OpenSession"),
            C_CloseSession = NativeLibrary.GetExport(libraryHandle, "C_CloseSession"),
            C_CloseAllSessions = NativeLibrary.GetExport(libraryHandle, "C_CloseAllSessions"),
            C_GetSessionInfo = NativeLibrary.GetExport(libraryHandle, "C_GetSessionInfo"),
            C_GetOperationState = NativeLibrary.GetExport(libraryHandle, "C_GetOperationState"),
            C_SetOperationState = NativeLibrary.GetExport(libraryHandle, "C_SetOperationState"),
            C_Login = NativeLibrary.GetExport(libraryHandle, "C_Login"),
            C_Logout = NativeLibrary.GetExport(libraryHandle, "C_Logout"),
            C_CreateObject = NativeLibrary.GetExport(libraryHandle, "C_CreateObject"),
            C_CopyObject = NativeLibrary.GetExport(libraryHandle, "C_CopyObject"),
            C_DestroyObject = NativeLibrary.GetExport(libraryHandle, "C_DestroyObject"),
            C_GetObjectSize = NativeLibrary.GetExport(libraryHandle, "C_GetObjectSize"),
            C_GetAttributeValue = NativeLibrary.GetExport(libraryHandle, "C_GetAttributeValue"),
            C_SetAttributeValue = NativeLibrary.GetExport(libraryHandle, "C_SetAttributeValue"),
            C_FindObjectsInit = NativeLibrary.GetExport(libraryHandle, "C_FindObjectsInit"),
            C_FindObjects = NativeLibrary.GetExport(libraryHandle, "C_FindObjects"),
            C_FindObjectsFinal = NativeLibrary.GetExport(libraryHandle, "C_FindObjectsFinal"),
            C_EncryptInit = NativeLibrary.GetExport(libraryHandle, "C_EncryptInit"),
            C_Encrypt = NativeLibrary.GetExport(libraryHandle, "C_Encrypt"),
            C_EncryptUpdate = NativeLibrary.GetExport(libraryHandle, "C_EncryptUpdate"),
            C_EncryptFinal = NativeLibrary.GetExport(libraryHandle, "C_EncryptFinal"),
            C_DecryptInit = NativeLibrary.GetExport(libraryHandle, "C_DecryptInit"),
            C_Decrypt = NativeLibrary.GetExport(libraryHandle, "C_Decrypt"),
            C_DecryptUpdate = NativeLibrary.GetExport(libraryHandle, "C_DecryptUpdate"),
            C_DecryptFinal = NativeLibrary.GetExport(libraryHandle, "C_DecryptFinal"),
            C_DigestInit = NativeLibrary.GetExport(libraryHandle, "C_DigestInit"),
            C_Digest = NativeLibrary.GetExport(libraryHandle, "C_Digest"),
            C_DigestUpdate = NativeLibrary.GetExport(libraryHandle, "C_DigestUpdate"),
            C_DigestKey = NativeLibrary.GetExport(libraryHandle, "C_DigestKey"),
            C_DigestFinal = NativeLibrary.GetExport(libraryHandle, "C_DigestFinal"),
            C_SignInit = NativeLibrary.GetExport(libraryHandle, "C_SignInit"),
            C_Sign = NativeLibrary.GetExport(libraryHandle, "C_Sign"),
            C_SignUpdate = NativeLibrary.GetExport(libraryHandle, "C_SignUpdate"),
            C_SignFinal = NativeLibrary.GetExport(libraryHandle, "C_SignFinal"),
            C_SignRecoverInit = NativeLibrary.GetExport(libraryHandle, "C_SignRecoverInit"),
            C_SignRecover = NativeLibrary.GetExport(libraryHandle, "C_SignRecover"),
            C_VerifyInit = NativeLibrary.GetExport(libraryHandle, "C_VerifyInit"),
            C_Verify = NativeLibrary.GetExport(libraryHandle, "C_Verify"),
            C_VerifyUpdate = NativeLibrary.GetExport(libraryHandle, "C_VerifyUpdate"),
            C_VerifyFinal = NativeLibrary.GetExport(libraryHandle, "C_VerifyFinal"),
            C_VerifyRecoverInit = NativeLibrary.GetExport(libraryHandle, "C_VerifyRecoverInit"),
            C_VerifyRecover = NativeLibrary.GetExport(libraryHandle, "C_VerifyRecover"),
            C_DigestEncryptUpdate = NativeLibrary.GetExport(libraryHandle, "C_DigestEncryptUpdate"),
            C_DecryptDigestUpdate = NativeLibrary.GetExport(libraryHandle, "C_DecryptDigestUpdate"),
            C_SignEncryptUpdate = NativeLibrary.GetExport(libraryHandle, "C_SignEncryptUpdate"),
            C_DecryptVerifyUpdate = NativeLibrary.GetExport(libraryHandle, "C_DecryptVerifyUpdate"),
            C_GenerateKey = NativeLibrary.GetExport(libraryHandle, "C_GenerateKey"),
            C_GenerateKeyPair = NativeLibrary.GetExport(libraryHandle, "C_GenerateKeyPair"),
            C_WrapKey = NativeLibrary.GetExport(libraryHandle, "C_WrapKey"),
            C_UnwrapKey = NativeLibrary.GetExport(libraryHandle, "C_UnwrapKey"),
            C_DeriveKey = NativeLibrary.GetExport(libraryHandle, "C_DeriveKey"),
            C_SeedRandom = NativeLibrary.GetExport(libraryHandle, "C_SeedRandom"),
            C_GenerateRandom = NativeLibrary.GetExport(libraryHandle, "C_GenerateRandom"),
            C_GetFunctionStatus = NativeLibrary.GetExport(libraryHandle, "C_GetFunctionStatus"),
            C_CancelFunction = NativeLibrary.GetExport(libraryHandle, "C_CancelFunction"),
            C_WaitForSlotEvent = NativeLibrary.GetExport(libraryHandle, "C_WaitForSlotEvent")
        };

        Initialize(funcList);
    }

    /// <summary>
    /// Get delegates without C_GetFunctionList function from the statically linked PKCS#11 library
    /// </summary>
    private void InitializeWithoutGetFunctionList()
    {
        C_Initialize = NativeMethods.C_Initialize;
        C_Finalize = NativeMethods.C_Finalize;
        C_GetInfo = NativeMethods.C_GetInfo;
        C_GetFunctionList = NativeMethods.C_GetFunctionList;
        C_GetSlotList = NativeMethods.C_GetSlotList;
        C_GetSlotInfo = NativeMethods.C_GetSlotInfo;
        C_GetTokenInfo = NativeMethods.C_GetTokenInfo;
        C_GetMechanismList = NativeMethods.C_GetMechanismList;
        C_GetMechanismInfo = NativeMethods.C_GetMechanismInfo;
        C_InitToken = NativeMethods.C_InitToken;
        C_InitPIN = NativeMethods.C_InitPIN;
        C_SetPIN = NativeMethods.C_SetPIN;
        C_OpenSession = NativeMethods.C_OpenSession;
        C_CloseSession = NativeMethods.C_CloseSession;
        C_CloseAllSessions = NativeMethods.C_CloseAllSessions;
        C_GetSessionInfo = NativeMethods.C_GetSessionInfo;
        C_GetOperationState = NativeMethods.C_GetOperationState;
        C_SetOperationState = NativeMethods.C_SetOperationState;
        C_Login = NativeMethods.C_Login;
        C_Logout = NativeMethods.C_Logout;
        C_CreateObject = NativeMethods.C_CreateObject;
        C_CopyObject = NativeMethods.C_CopyObject;
        C_DestroyObject = NativeMethods.C_DestroyObject;
        C_GetObjectSize = NativeMethods.C_GetObjectSize;
        C_GetAttributeValue = NativeMethods.C_GetAttributeValue;
        C_SetAttributeValue = NativeMethods.C_SetAttributeValue;
        C_FindObjectsInit = NativeMethods.C_FindObjectsInit;
        C_FindObjects = NativeMethods.C_FindObjects;
        C_FindObjectsFinal = NativeMethods.C_FindObjectsFinal;
        C_EncryptInit = NativeMethods.C_EncryptInit;
        C_Encrypt = NativeMethods.C_Encrypt;
        C_EncryptUpdate = NativeMethods.C_EncryptUpdate;
        C_EncryptFinal = NativeMethods.C_EncryptFinal;
        C_DecryptInit = NativeMethods.C_DecryptInit;
        C_Decrypt = NativeMethods.C_Decrypt;
        C_DecryptUpdate = NativeMethods.C_DecryptUpdate;
        C_DecryptFinal = NativeMethods.C_DecryptFinal;
        C_DigestInit = NativeMethods.C_DigestInit;
        C_Digest = NativeMethods.C_Digest;
        C_DigestUpdate = NativeMethods.C_DigestUpdate;
        C_DigestKey = NativeMethods.C_DigestKey;
        C_DigestFinal = NativeMethods.C_DigestFinal;
        C_SignInit = NativeMethods.C_SignInit;
        C_Sign = NativeMethods.C_Sign;
        C_SignUpdate = NativeMethods.C_SignUpdate;
        C_SignFinal = NativeMethods.C_SignFinal;
        C_SignRecoverInit = NativeMethods.C_SignRecoverInit;
        C_SignRecover = NativeMethods.C_SignRecover;
        C_VerifyInit = NativeMethods.C_VerifyInit;
        C_Verify = NativeMethods.C_Verify;
        C_VerifyUpdate = NativeMethods.C_VerifyUpdate;
        C_VerifyFinal = NativeMethods.C_VerifyFinal;
        C_VerifyRecoverInit = NativeMethods.C_VerifyRecoverInit;
        C_VerifyRecover = NativeMethods.C_VerifyRecover;
        C_DigestEncryptUpdate = NativeMethods.C_DigestEncryptUpdate;
        C_DecryptDigestUpdate = NativeMethods.C_DecryptDigestUpdate;
        C_SignEncryptUpdate = NativeMethods.C_SignEncryptUpdate;
        C_DecryptVerifyUpdate = NativeMethods.C_DecryptVerifyUpdate;
        C_GenerateKey = NativeMethods.C_GenerateKey;
        C_GenerateKeyPair = NativeMethods.C_GenerateKeyPair;
        C_WrapKey = NativeMethods.C_WrapKey;
        C_UnwrapKey = NativeMethods.C_UnwrapKey;
        C_DeriveKey = NativeMethods.C_DeriveKey;
        C_SeedRandom = NativeMethods.C_SeedRandom;
        C_GenerateRandom = NativeMethods.C_GenerateRandom;
        C_GetFunctionStatus = NativeMethods.C_GetFunctionStatus;
        C_CancelFunction = NativeMethods.C_CancelFunction;
        C_WaitForSlotEvent = NativeMethods.C_WaitForSlotEvent;
    }

    /// <summary>
    /// Get delegates from unmanaged function pointers
    /// </summary>
    /// <param name="funcList">Structure which contains cryptoki function pointers</param>
    private void Initialize(CK_FUNCTION_LIST funcList)
    {
        C_Initialize = Marshal.GetDelegateForFunctionPointer<C_InitializeDelegate>(funcList.C_Initialize);
        C_Finalize = Marshal.GetDelegateForFunctionPointer<C_FinalizeDelegate>(funcList.C_Finalize);
        C_GetInfo = Marshal.GetDelegateForFunctionPointer<C_GetInfoDelegate>(funcList.C_GetInfo);
        C_GetFunctionList = Marshal.GetDelegateForFunctionPointer<C_GetFunctionListDelegate>(funcList.C_GetFunctionList);
        C_GetSlotList = Marshal.GetDelegateForFunctionPointer<C_GetSlotListDelegate>(funcList.C_GetSlotList);
        C_GetSlotInfo = Marshal.GetDelegateForFunctionPointer<C_GetSlotInfoDelegate>(funcList.C_GetSlotInfo);
        C_GetTokenInfo = Marshal.GetDelegateForFunctionPointer<C_GetTokenInfoDelegate>(funcList.C_GetTokenInfo);
        C_GetMechanismList = Marshal.GetDelegateForFunctionPointer<C_GetMechanismListDelegate>(funcList.C_GetMechanismList);
        C_GetMechanismInfo = Marshal.GetDelegateForFunctionPointer<C_GetMechanismInfoDelegate>(funcList.C_GetMechanismInfo);
        C_InitToken = Marshal.GetDelegateForFunctionPointer<C_InitTokenDelegate>(funcList.C_InitToken);
        C_InitPIN = Marshal.GetDelegateForFunctionPointer<C_InitPINDelegate>(funcList.C_InitPIN);
        C_SetPIN = Marshal.GetDelegateForFunctionPointer<C_SetPINDelegate>(funcList.C_SetPIN);
        C_OpenSession = Marshal.GetDelegateForFunctionPointer<C_OpenSessionDelegate>(funcList.C_OpenSession);
        C_CloseSession = Marshal.GetDelegateForFunctionPointer<C_CloseSessionDelegate>(funcList.C_CloseSession);
        C_CloseAllSessions = Marshal.GetDelegateForFunctionPointer<C_CloseAllSessionsDelegate>(funcList.C_CloseAllSessions);
        C_GetSessionInfo = Marshal.GetDelegateForFunctionPointer<C_GetSessionInfoDelegate>(funcList.C_GetSessionInfo);
        C_GetOperationState = Marshal.GetDelegateForFunctionPointer<C_GetOperationStateDelegate>(funcList.C_GetOperationState);
        C_SetOperationState = Marshal.GetDelegateForFunctionPointer<C_SetOperationStateDelegate>(funcList.C_SetOperationState);
        C_Login = Marshal.GetDelegateForFunctionPointer<C_LoginDelegate>(funcList.C_Login);
        C_Logout = Marshal.GetDelegateForFunctionPointer<C_LogoutDelegate>(funcList.C_Logout);
        C_CreateObject = Marshal.GetDelegateForFunctionPointer<C_CreateObjectDelegate>(funcList.C_CreateObject);
        C_CopyObject = Marshal.GetDelegateForFunctionPointer<C_CopyObjectDelegate>(funcList.C_CopyObject);
        C_DestroyObject = Marshal.GetDelegateForFunctionPointer<C_DestroyObjectDelegate>(funcList.C_DestroyObject);
        C_GetObjectSize = Marshal.GetDelegateForFunctionPointer<C_GetObjectSizeDelegate>(funcList.C_GetObjectSize);
        C_GetAttributeValue = Marshal.GetDelegateForFunctionPointer<C_GetAttributeValueDelegate>(funcList.C_GetAttributeValue);
        C_SetAttributeValue = Marshal.GetDelegateForFunctionPointer<C_SetAttributeValueDelegate>(funcList.C_SetAttributeValue);
        C_FindObjectsInit = Marshal.GetDelegateForFunctionPointer<C_FindObjectsInitDelegate>(funcList.C_FindObjectsInit);
        C_FindObjects = Marshal.GetDelegateForFunctionPointer<C_FindObjectsDelegate>(funcList.C_FindObjects);
        C_FindObjectsFinal = Marshal.GetDelegateForFunctionPointer<C_FindObjectsFinalDelegate>(funcList.C_FindObjectsFinal);
        C_EncryptInit = Marshal.GetDelegateForFunctionPointer<C_EncryptInitDelegate>(funcList.C_EncryptInit);
        C_Encrypt = Marshal.GetDelegateForFunctionPointer<C_EncryptDelegate>(funcList.C_Encrypt);
        C_EncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_EncryptUpdateDelegate>(funcList.C_EncryptUpdate);
        C_EncryptFinal = Marshal.GetDelegateForFunctionPointer<C_EncryptFinalDelegate>(funcList.C_EncryptFinal);
        C_DecryptInit = Marshal.GetDelegateForFunctionPointer<C_DecryptInitDelegate>(funcList.C_DecryptInit);
        C_Decrypt = Marshal.GetDelegateForFunctionPointer<C_DecryptDelegate>(funcList.C_Decrypt);
        C_DecryptUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptUpdateDelegate>(funcList.C_DecryptUpdate);
        C_DecryptFinal = Marshal.GetDelegateForFunctionPointer<C_DecryptFinalDelegate>(funcList.C_DecryptFinal);
        C_DigestInit = Marshal.GetDelegateForFunctionPointer<C_DigestInitDelegate>(funcList.C_DigestInit);
        C_Digest = Marshal.GetDelegateForFunctionPointer<C_DigestDelegate>(funcList.C_Digest);
        C_DigestUpdate = Marshal.GetDelegateForFunctionPointer<C_DigestUpdateDelegate>(funcList.C_DigestUpdate);
        C_DigestKey = Marshal.GetDelegateForFunctionPointer<C_DigestKeyDelegate>(funcList.C_DigestKey);
        C_DigestFinal = Marshal.GetDelegateForFunctionPointer<C_DigestFinalDelegate>(funcList.C_DigestFinal);
        C_SignInit = Marshal.GetDelegateForFunctionPointer<C_SignInitDelegate>(funcList.C_SignInit);
        C_Sign = Marshal.GetDelegateForFunctionPointer<C_SignDelegate>(funcList.C_Sign);
        C_SignUpdate = Marshal.GetDelegateForFunctionPointer<C_SignUpdateDelegate>(funcList.C_SignUpdate);
        C_SignFinal = Marshal.GetDelegateForFunctionPointer<C_SignFinalDelegate>(funcList.C_SignFinal);
        C_SignRecoverInit = Marshal.GetDelegateForFunctionPointer<C_SignRecoverInitDelegate>(funcList.C_SignRecoverInit);
        C_SignRecover = Marshal.GetDelegateForFunctionPointer<C_SignRecoverDelegate>(funcList.C_SignRecover);
        C_VerifyInit = Marshal.GetDelegateForFunctionPointer<C_VerifyInitDelegate>(funcList.C_VerifyInit);
        C_Verify = Marshal.GetDelegateForFunctionPointer<C_VerifyDelegate>(funcList.C_Verify);
        C_VerifyUpdate = Marshal.GetDelegateForFunctionPointer<C_VerifyUpdateDelegate>(funcList.C_VerifyUpdate);
        C_VerifyFinal = Marshal.GetDelegateForFunctionPointer<C_VerifyFinalDelegate>(funcList.C_VerifyFinal);
        C_VerifyRecoverInit = Marshal.GetDelegateForFunctionPointer<C_VerifyRecoverInitDelegate>(funcList.C_VerifyRecoverInit);
        C_VerifyRecover = Marshal.GetDelegateForFunctionPointer<C_VerifyRecoverDelegate>(funcList.C_VerifyRecover);
        C_DigestEncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_DigestEncryptUpdateDelegate>(funcList.C_DigestEncryptUpdate);
        C_DecryptDigestUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptDigestUpdateDelegate>(funcList.C_DecryptDigestUpdate);
        C_SignEncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_SignEncryptUpdateDelegate>(funcList.C_SignEncryptUpdate);
        C_DecryptVerifyUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptVerifyUpdateDelegate>(funcList.C_DecryptVerifyUpdate);
        C_GenerateKey = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyDelegate>(funcList.C_GenerateKey);
        C_GenerateKeyPair = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyPairDelegate>(funcList.C_GenerateKeyPair);
        C_WrapKey = Marshal.GetDelegateForFunctionPointer<C_WrapKeyDelegate>(funcList.C_WrapKey);
        C_UnwrapKey = Marshal.GetDelegateForFunctionPointer<C_UnwrapKeyDelegate>(funcList.C_UnwrapKey);
        C_DeriveKey = Marshal.GetDelegateForFunctionPointer<C_DeriveKeyDelegate>(funcList.C_DeriveKey);
        C_SeedRandom = Marshal.GetDelegateForFunctionPointer<C_SeedRandomDelegate>(funcList.C_SeedRandom);
        C_GenerateRandom = Marshal.GetDelegateForFunctionPointer<C_GenerateRandomDelegate>(funcList.C_GenerateRandom);
        C_GetFunctionStatus = Marshal.GetDelegateForFunctionPointer<C_GetFunctionStatusDelegate>(funcList.C_GetFunctionStatus);
        C_CancelFunction = Marshal.GetDelegateForFunctionPointer<C_CancelFunctionDelegate>(funcList.C_CancelFunction);
        C_WaitForSlotEvent = Marshal.GetDelegateForFunctionPointer<C_WaitForSlotEventDelegate>(funcList.C_WaitForSlotEvent);
    }
}