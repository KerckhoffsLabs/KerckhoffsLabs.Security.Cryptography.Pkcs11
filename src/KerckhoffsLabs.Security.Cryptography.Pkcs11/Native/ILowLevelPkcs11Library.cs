using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Abstraction over the low-level PKCS#11 dispatch surface (<see cref="LowLevelPkcs11Library"/>).
/// Exists as a testing seam: high-level types (<c>Pkcs11Session</c>, <c>Pkcs11Slot</c>,
/// <c>Pkcs11Library</c>) depend on this interface so unit tests can substitute a fake that
/// returns specific <see cref="CKR"/> codes (e.g. <c>CKR_BUFFER_TOO_SMALL</c> from a
/// two-call size probe) without a live token. Mirrors the full public surface of the
/// single production implementation; not intended as an extensibility point for consumers.
/// </summary>
internal interface ILowLevelPkcs11Library : IDisposable
{
    /// <summary>True when the token exposes the PKCS#11 v3.0 message-based AEAD surface.</summary>
    bool IsMessageApiSupported { get; }
    bool IsV32ApiSupported { get; }

    // ---- Session tracking: registration + teardown seam ----
    /// <summary>Count of still-live tracked session handles (test/diagnostic seam).</summary>
    int TrackedSessionCount { get; }
    /// <summary>Registers a session handle for cleanup at library teardown.</summary>
    void RegisterSession(Pkcs11SessionHandle handle);
    /// <summary>Removes a session handle from the tracker after a normal close.</summary>
    void UnregisterSession(Pkcs11SessionHandle handle);
    /// <summary>Closes every still-live tracked session before C_Finalize / module unload.</summary>
    void CloseAllTrackedSessions();

    // ---- Cryptoki dispatch ----
    CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs);
    CKR C_Finalize(IntPtr reserved);
    CKR C_GetInfo(ref CK_INFO info);
    CKR C_GetFunctionList(out IntPtr functionList);
    CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count);
    CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info);
    CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info);
    CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count);
    CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info);
    CKR C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label);
    CKR C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen);
    CKR C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen);
    CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session);
    CKR C_CloseSession(NativeCULong session);
    CKR C_CloseAllSessions(NativeCULong slotId);
    CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info);
    CKR C_GetOperationState(NativeCULong session, byte[]? operationState, ref NativeCULong operationStateLen);
    CKR C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey);
    CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen);
    CKR C_LoginUser(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen);
    CKR C_SessionCancel(NativeCULong session, NativeCULong flags);
    CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen);
    CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen);
    CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags);
    CKR C_MessageEncryptFinal(NativeCULong session);
    CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen);
    CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen);
    CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags);
    CKR C_MessageDecryptFinal(NativeCULong session);
    CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen);
    CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);
    CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen);
    CKR C_MessageSignFinal(NativeCULong session);
    CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);
    CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);
    CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);
    CKR C_MessageVerifyFinal(NativeCULong session);
    CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey);
    CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey);
    CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen);
    CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen);
    CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen);
    CKR C_VerifySignatureFinal(NativeCULong session);
    CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags);
    CKR C_AsyncComplete(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result);
    CKR C_AsyncGetID(NativeCULong session, byte[] functionName, ref NativeCULong id);
    CKR C_AsyncJoin(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen);
    CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen);
    CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key);
    CKR C_Logout(NativeCULong session);
    CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong objectId);
    CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong newObjectId);
    CKR C_DestroyObject(NativeCULong session, NativeCULong objectId);
    CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size);
    CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count);
    CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count);
    CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count);
    CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount);
    CKR C_FindObjectsFinal(NativeCULong session);
    CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encryptedData, ref NativeCULong encryptedDataLen);
    CKR C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen);
    CKR C_EncryptFinal(NativeCULong session, byte[]? lastEncryptedPart, ref NativeCULong lastEncryptedPartLen);
    CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[]? data, ref NativeCULong dataLen);
    CKR C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen);
    CKR C_DecryptFinal(NativeCULong session, byte[]? lastPart, ref NativeCULong lastPartLen);
    CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism);
    CKR C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? digest, ref NativeCULong digestLen);
    CKR C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen);
    CKR C_DigestKey(NativeCULong session, NativeCULong key);
    CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen);
    CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen);
    CKR C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen);
    CKR C_SignFinal(NativeCULong session, byte[]? signature, ref NativeCULong signatureLen);
    CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen);
    CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);
    CKR C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen);
    CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen);
    CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[]? data, ref NativeCULong dataLen);
    CKR C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen);
    CKR C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen);
    CKR C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen);
    CKR C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen);
    CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key);
    CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[]? privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey);
    CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen);
    CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key);
    CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key);
    CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen);
    CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen);
    CKR C_GetFunctionStatus(NativeCULong session);
    CKR C_CancelFunction(NativeCULong session);
    CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);
}
