using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// Base managed <see cref="ILowLevelPkcs11Library"/> where every Cryptoki entry point returns
/// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>. Derive and override only the functions a given
/// fake token needs (see <c>ManagedSoftToken</c>). Generated from the interface so the
/// signatures stay in lock-step; regenerate if ILowLevelPkcs11Library changes.
/// </summary>
internal abstract class NotSupportedPkcs11Library : ILowLevelPkcs11Library
{
    public virtual bool IsMessageApiSupported => false;
    public virtual bool IsV32ApiSupported => false;
    public virtual int TrackedSessionCount => 0;
    public virtual void RegisterSession(Pkcs11SessionHandle handle) { }
    public virtual void UnregisterSession(Pkcs11SessionHandle handle) { }
    public virtual void CloseAllTrackedSessions() { }
    public virtual void Dispose() { }

    public virtual CKR C_GetFunctionList(out IntPtr functionList) { functionList = IntPtr.Zero; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }

    public virtual CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Finalize(IntPtr reserved) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetInfo(ref CK_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CloseSession(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CloseAllSessions(NativeCULong slotId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetOperationState(NativeCULong session, byte[]? operationState, ref NativeCULong operationStateLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_LoginUser(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageEncryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageSignFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageVerifyFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncComplete(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncGetID(NativeCULong session, byte[] functionName, ref NativeCULong id) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncJoin(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Logout(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong newObjectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encryptedData, ref NativeCULong encryptedDataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptFinal(NativeCULong session, byte[]? lastEncryptedPart, ref NativeCULong lastEncryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[]? data, ref NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptFinal(NativeCULong session, byte[]? lastPart, ref NativeCULong lastPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? digest, ref NativeCULong digestLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestKey(NativeCULong session, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignFinal(NativeCULong session, byte[]? signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[]? data, ref NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[]? privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetFunctionStatus(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CancelFunction(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
}
