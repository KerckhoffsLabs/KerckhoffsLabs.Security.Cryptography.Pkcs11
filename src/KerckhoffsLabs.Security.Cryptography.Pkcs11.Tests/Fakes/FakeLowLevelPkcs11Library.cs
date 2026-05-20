using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fakes;

/// <summary>
/// Test double for <see cref="ILowLevelPkcs11Library"/>. Every cryptoki method throws
/// <see cref="NotSupportedException"/> by default so an unexpected call surfaces loudly;
/// a test overrides only the methods its scenario exercises. Session-tracking members are
/// no-ops so a <c>Pkcs11Session</c> can be constructed over the fake.
/// </summary>
internal class FakeLowLevelPkcs11Library : ILowLevelPkcs11Library
{
    public virtual bool IsMessageApiSupported => false;
    public virtual bool IsV32ApiSupported => true;
    public virtual int TrackedSessionCount => 0;
    public virtual void RegisterSession(Pkcs11SessionHandle handle) { }
    public virtual void UnregisterSession(Pkcs11SessionHandle handle) { }
    public virtual void CloseAllTrackedSessions() { }
    public virtual void Dispose() { }

    public virtual CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => throw new NotSupportedException("C_Initialize");
    public virtual CKR C_Finalize(IntPtr reserved) => throw new NotSupportedException("C_Finalize");
    public virtual CKR C_GetInfo(ref CK_INFO info) => throw new NotSupportedException("C_GetInfo");
    public virtual CKR C_GetFunctionList(out IntPtr functionList) => throw new NotSupportedException("C_GetFunctionList");
    public virtual CKR C_GetSlotList(bool tokenPresent, NativeCULong[] slotList, ref NativeCULong count) => throw new NotSupportedException("C_GetSlotList");
    public virtual CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info) => throw new NotSupportedException("C_GetSlotInfo");
    public virtual CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info) => throw new NotSupportedException("C_GetTokenInfo");
    public virtual CKR C_GetMechanismList(NativeCULong slotId, CKM[] mechanismList, ref NativeCULong count) => throw new NotSupportedException("C_GetMechanismList");
    public virtual CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info) => throw new NotSupportedException("C_GetMechanismInfo");
    public virtual CKR C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label) => throw new NotSupportedException("C_InitToken");
    public virtual CKR C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen) => throw new NotSupportedException("C_InitPIN");
    public virtual CKR C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen) => throw new NotSupportedException("C_SetPIN");
    public virtual CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session) => throw new NotSupportedException("C_OpenSession");
    public virtual CKR C_CloseSession(NativeCULong session) => throw new NotSupportedException("C_CloseSession");
    public virtual CKR C_CloseAllSessions(NativeCULong slotId) => throw new NotSupportedException("C_CloseAllSessions");
    public virtual CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => throw new NotSupportedException("C_GetSessionInfo");
    public virtual CKR C_GetOperationState(NativeCULong session, byte[] operationState, ref NativeCULong operationStateLen) => throw new NotSupportedException("C_GetOperationState");
    public virtual CKR C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey) => throw new NotSupportedException("C_SetOperationState");
    public virtual CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen) => throw new NotSupportedException("C_Login");
    public virtual CKR C_LoginUser(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen) => throw new NotSupportedException("C_LoginUser");
    public virtual CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => throw new NotSupportedException("C_SessionCancel");
    public virtual CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_MessageEncryptInit");
    public virtual CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen) => throw new NotSupportedException("C_EncryptMessage");
    public virtual CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen) => throw new NotSupportedException("C_EncryptMessageBegin");
    public virtual CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags) => throw new NotSupportedException("C_EncryptMessageNext");
    public virtual CKR C_MessageEncryptFinal(NativeCULong session) => throw new NotSupportedException("C_MessageEncryptFinal");
    public virtual CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_MessageDecryptInit");
    public virtual CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen) => throw new NotSupportedException("C_DecryptMessage");
    public virtual CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen) => throw new NotSupportedException("C_DecryptMessageBegin");
    public virtual CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags) => throw new NotSupportedException("C_DecryptMessageNext");
    public virtual CKR C_MessageDecryptFinal(NativeCULong session) => throw new NotSupportedException("C_MessageDecryptFinal");
    public virtual CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_MessageSignInit");
    public virtual CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen) => throw new NotSupportedException("C_SignMessage");
    public virtual CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => throw new NotSupportedException("C_SignMessageBegin");
    public virtual CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen) => throw new NotSupportedException("C_SignMessageNext");
    public virtual CKR C_MessageSignFinal(NativeCULong session) => throw new NotSupportedException("C_MessageSignFinal");
    public virtual CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_MessageVerifyInit");
    public virtual CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => throw new NotSupportedException("C_VerifyMessage");
    public virtual CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => throw new NotSupportedException("C_VerifyMessageBegin");
    public virtual CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => throw new NotSupportedException("C_VerifyMessageNext");
    public virtual CKR C_MessageVerifyFinal(NativeCULong session) => throw new NotSupportedException("C_MessageVerifyFinal");
    public virtual CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey) => throw new NotSupportedException("C_EncapsulateKey");
    public virtual CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey) => throw new NotSupportedException("C_DecapsulateKey");
    public virtual CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen) => throw new NotSupportedException("C_VerifySignatureInit");
    public virtual CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen) => throw new NotSupportedException("C_VerifySignature");
    public virtual CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => throw new NotSupportedException("C_VerifySignatureUpdate");
    public virtual CKR C_VerifySignatureFinal(NativeCULong session) => throw new NotSupportedException("C_VerifySignatureFinal");
    public virtual CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags) => throw new NotSupportedException("C_GetSessionValidationFlags");
    public virtual CKR C_AsyncComplete(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result) => throw new NotSupportedException("C_AsyncComplete");
    public virtual CKR C_AsyncGetID(NativeCULong session, byte[] functionName, ref NativeCULong id) => throw new NotSupportedException("C_AsyncGetID");
    public virtual CKR C_AsyncJoin(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen) => throw new NotSupportedException("C_AsyncJoin");
    public virtual CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[] wrappedKey, ref NativeCULong wrappedKeyLen) => throw new NotSupportedException("C_WrapKeyAuthenticated");
    public virtual CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key) => throw new NotSupportedException("C_UnwrapKeyAuthenticated");
    public virtual CKR C_Logout(NativeCULong session) => throw new NotSupportedException("C_Logout");
    public virtual CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong objectId) => throw new NotSupportedException("C_CreateObject");
    public virtual CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong newObjectId) => throw new NotSupportedException("C_CopyObject");
    public virtual CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => throw new NotSupportedException("C_DestroyObject");
    public virtual CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size) => throw new NotSupportedException("C_GetObjectSize");
    public virtual CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count) => throw new NotSupportedException("C_GetAttributeValue");
    public virtual CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count) => throw new NotSupportedException("C_SetAttributeValue");
    public virtual CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count) => throw new NotSupportedException("C_FindObjectsInit");
    public virtual CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount) => throw new NotSupportedException("C_FindObjects");
    public virtual CKR C_FindObjectsFinal(NativeCULong session) => throw new NotSupportedException("C_FindObjectsFinal");
    public virtual CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_EncryptInit");
    public virtual CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] encryptedData, ref NativeCULong encryptedDataLen) => throw new NotSupportedException("C_Encrypt");
    public virtual CKR C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => throw new NotSupportedException("C_EncryptUpdate");
    public virtual CKR C_EncryptFinal(NativeCULong session, byte[] lastEncryptedPart, ref NativeCULong lastEncryptedPartLen) => throw new NotSupportedException("C_EncryptFinal");
    public virtual CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_DecryptInit");
    public virtual CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[] data, ref NativeCULong dataLen) => throw new NotSupportedException("C_Decrypt");
    public virtual CKR C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => throw new NotSupportedException("C_DecryptUpdate");
    public virtual CKR C_DecryptFinal(NativeCULong session, byte[] lastPart, ref NativeCULong lastPartLen) => throw new NotSupportedException("C_DecryptFinal");
    public virtual CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => throw new NotSupportedException("C_DigestInit");
    public virtual CKR C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] digest, ref NativeCULong digestLen) => throw new NotSupportedException("C_Digest");
    public virtual CKR C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => throw new NotSupportedException("C_DigestUpdate");
    public virtual CKR C_DigestKey(NativeCULong session, NativeCULong key) => throw new NotSupportedException("C_DigestKey");
    public virtual CKR C_DigestFinal(NativeCULong session, byte[] digest, ref NativeCULong digestLen) => throw new NotSupportedException("C_DigestFinal");
    public virtual CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_SignInit");
    public virtual CKR C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen) => throw new NotSupportedException("C_Sign");
    public virtual CKR C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => throw new NotSupportedException("C_SignUpdate");
    public virtual CKR C_SignFinal(NativeCULong session, byte[] signature, ref NativeCULong signatureLen) => throw new NotSupportedException("C_SignFinal");
    public virtual CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_SignRecoverInit");
    public virtual CKR C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen) => throw new NotSupportedException("C_SignRecover");
    public virtual CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_VerifyInit");
    public virtual CKR C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => throw new NotSupportedException("C_Verify");
    public virtual CKR C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen) => throw new NotSupportedException("C_VerifyUpdate");
    public virtual CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen) => throw new NotSupportedException("C_VerifyFinal");
    public virtual CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => throw new NotSupportedException("C_VerifyRecoverInit");
    public virtual CKR C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[] data, ref NativeCULong dataLen) => throw new NotSupportedException("C_VerifyRecover");
    public virtual CKR C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => throw new NotSupportedException("C_DigestEncryptUpdate");
    public virtual CKR C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => throw new NotSupportedException("C_DecryptDigestUpdate");
    public virtual CKR C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen) => throw new NotSupportedException("C_SignEncryptUpdate");
    public virtual CKR C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen) => throw new NotSupportedException("C_DecryptVerifyUpdate");
    public virtual CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong key) => throw new NotSupportedException("C_GenerateKey");
    public virtual CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[] privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey) => throw new NotSupportedException("C_GenerateKeyPair");
    public virtual CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] wrappedKey, ref NativeCULong wrappedKeyLen) => throw new NotSupportedException("C_WrapKey");
    public virtual CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key) => throw new NotSupportedException("C_UnwrapKey");
    public virtual CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, ref NativeCULong key) => throw new NotSupportedException("C_DeriveKey");
    public virtual CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen) => throw new NotSupportedException("C_SeedRandom");
    public virtual CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen) => throw new NotSupportedException("C_GenerateRandom");
    public virtual CKR C_GetFunctionStatus(NativeCULong session) => throw new NotSupportedException("C_GetFunctionStatus");
    public virtual CKR C_CancelFunction(NativeCULong session) => throw new NotSupportedException("C_CancelFunction");
    public virtual CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved) => throw new NotSupportedException("C_WaitForSlotEvent");
}
