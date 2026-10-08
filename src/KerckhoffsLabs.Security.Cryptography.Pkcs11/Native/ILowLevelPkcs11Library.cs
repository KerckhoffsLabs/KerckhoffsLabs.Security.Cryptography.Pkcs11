using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

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

    /// <summary>
    /// The module this library calls into. Sessions reference and are tracked by it, whichever
    /// implementation sits behind this interface.
    /// </summary>
    Pkcs11ModuleHandle Module { get; }
    /// <summary>
    /// Finalizes the module once nothing uses it any more: no call in flight and no session open. A test
    /// double has no such references to wait for, so by default it finalizes at once.
    /// </summary>
    void FinalizeOnLastRelease() => C_Finalize(IntPtr.Zero);

    // ---- Cryptoki dispatch ----
    CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs);
    CKR C_Finalize(IntPtr reserved);
    CKR C_GetInfo(ref CK_INFO info);
    CKR C_GetSlotList(bool tokenPresent, Span<NativeCULong> slotList, out NativeCULong count);
    CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info);
    CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info);
    CKR C_GetMechanismList(NativeCULong slotId, Span<CKM> mechanismList, out NativeCULong count);
    CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info);
    CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label);
    CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin);
    CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin);
    CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, ref NativeCULong session);
    CKR C_CloseSession(NativeCULong session);
    CKR C_CloseAllSessions(NativeCULong slotId);
    CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info);
    CKR C_GetOperationState(NativeCULong session, Span<byte> operationState, bool lengthOnly, out NativeCULong operationStateLen);
    CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey, NativeCULong authenticationKey);
    CKR C_Login(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin);
    CKR C_LoginUser(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username);
    CKR C_SessionCancel(NativeCULong session, NativeCULong flags);
    CKR C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count);
    CKR C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface);
    CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, bool lengthOnly, out NativeCULong ciphertextLen);
    CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData);
    CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart,
        Span<byte> ciphertextPart, bool lengthOnly, out NativeCULong ciphertextPartLen, NativeCULong flags);
    CKR C_MessageEncryptFinal(NativeCULong session);
    CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, bool lengthOnly, out NativeCULong plaintextLen);
    CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData);
    CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart,
        Span<byte> plaintextPart, bool lengthOnly, out NativeCULong plaintextPartLen, NativeCULong flags);
    CKR C_MessageDecryptFinal(NativeCULong session);
    CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        out NativeCULong signatureLen);
    CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);
    CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        out NativeCULong signatureLen);
    CKR C_MessageSignFinal(NativeCULong session);
    CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
    CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);
    CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
    CKR C_MessageVerifyFinal(NativeCULong session);
    CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        Span<byte> ciphertext, bool lengthOnly, out NativeCULong ciphertextLen, ref NativeCULong derivedKey);
    CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey);
    CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature);
    CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data);
    CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part);
    CKR C_VerifySignatureFinal(NativeCULong session);
    CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags);
    CKR C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result);
    CKR C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id);
    CKR C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data);
    CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, bool lengthOnly, out NativeCULong wrappedKeyLen);
    CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key);
    CKR C_Logout(NativeCULong session);
    CKR C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId);
    CKR C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong newObjectId);
    CKR C_DestroyObject(NativeCULong session, NativeCULong objectId);
    CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size);
    CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template);
    CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template);
    CKR C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template);
    CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, out NativeCULong objectCount);
    CKR C_FindObjectsFinal(NativeCULong session);
    CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, bool lengthOnly, out NativeCULong encryptedDataLen);
    CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen);
    CKR C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, bool lengthOnly, out NativeCULong lastEncryptedPartLen);
    CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, bool lengthOnly, out NativeCULong dataLen);
    CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen);
    CKR C_DecryptFinal(NativeCULong session, Span<byte> lastPart, bool lengthOnly, out NativeCULong lastPartLen);
    CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism);
    CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, bool lengthOnly, out NativeCULong digestLen);
    CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part);
    CKR C_DigestKey(NativeCULong session, NativeCULong key);
    CKR C_DigestFinal(NativeCULong session, Span<byte> digest, bool lengthOnly, out NativeCULong digestLen);
    CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen);
    CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part);
    CKR C_SignFinal(NativeCULong session, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen);
    CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen);
    CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
    CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part);
    CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature);
    CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);
    CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, bool lengthOnly, out NativeCULong dataLen);
    CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen);
    CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen);
    CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen);
    CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen);
    CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key);
    CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey);
    CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, Span<byte> wrappedKey,
        bool lengthOnly, out NativeCULong wrappedKeyLen);
    CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key);
    CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key);
    CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed);
    CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData);
    CKR C_GetFunctionStatus(NativeCULong session);
    CKR C_CancelFunction(NativeCULong session);
    CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);
}
