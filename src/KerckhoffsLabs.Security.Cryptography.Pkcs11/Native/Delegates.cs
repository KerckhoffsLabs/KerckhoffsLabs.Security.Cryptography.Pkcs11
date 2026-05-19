using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitializeDelegate(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetFunctionListDelegate(out IntPtr functionList);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSlotListDelegate([MarshalAs(UnmanagedType.U1)] bool tokenPresent, [In, Out] NativeCULong[] slotList, ref NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetMechanismListDelegate(NativeCULong slotId, [In, Out] NativeCULong[] mechanismList, ref NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitTokenDelegate(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_InitPINDelegate(NativeCULong session, byte[] pin, NativeCULong pinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetPINDelegate(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_OpenSessionDelegate(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session);


[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetOperationStateDelegate(NativeCULong session, [In, Out] byte[] operationState, ref NativeCULong operationStateLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetOperationStateDelegate(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_LoginDelegate(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen);

/// <summary>
/// C_GetInterface was added in PKCS#11 v3.0 — returns a typed function-list interface
/// the application can use, allowing the token to expose newer or vendor-specific
/// function tables independently of the legacy C_GetFunctionList path.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetInterfaceDelegate(byte[]? interfaceName, IntPtr version, out IntPtr interfacePtr, NativeCULong flags);

/// <summary>
/// C_LoginUser was added in PKCS#11 v3.0 — logs in by both user type and a free-form
/// username, supporting HSMs with named user accounts beyond the SO/User dichotomy.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_LoginUserDelegate(NativeCULong session, NativeCULong userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen);



[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CreateObjectDelegate(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong objectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CreateObjectDelegate_Windows(NativeCULong session, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong objectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CopyObjectDelegate(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count, ref NativeCULong newObjectId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_CopyObjectDelegate_Windows(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong newObjectId);


[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetObjectSizeDelegate(NativeCULong session, NativeCULong objectId, ref NativeCULong size);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetAttributeValueDelegate(NativeCULong session, NativeCULong objectId, [In, Out] CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetAttributeValueDelegate_Windows(NativeCULong session, NativeCULong objectId, [In, Out] CK_ATTRIBUTE_Windows[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetAttributeValueDelegate(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SetAttributeValueDelegate_Windows(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE_Windows[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsInitDelegate(NativeCULong session, CK_ATTRIBUTE[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsInitDelegate_Windows(NativeCULong session, CK_ATTRIBUTE_Windows[] template, NativeCULong count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_FindObjectsDelegate(NativeCULong session, [In, Out] NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount);


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
internal delegate NativeCULong C_WaitForSlotEventDelegate(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageEncryptInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptMessageDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptMessageBeginDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptMessageNextDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageEncryptFinalDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageDecryptInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptMessageDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptMessageBeginDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptMessageNextDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageDecryptFinalDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageSignInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignMessageDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignMessageBeginDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignMessageNextDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, ref NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageSignFinalDelegate(NativeCULong session);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageVerifyInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyMessageDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyMessageBeginDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyMessageNextDelegate(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageVerifyFinalDelegate(NativeCULong session);

/// <summary>ML-KEM-style key encapsulation (PKCS#11 v3.2 §5.18.10). Takes an encapsulating public key, returns ciphertext + a handle to the encapsulated shared-secret key.</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncapsulateKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, [In, Out] byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey);

/// <summary>ML-KEM-style key decapsulation (PKCS#11 v3.2 §5.18.11). Reverses C_EncapsulateKey using the matching private key.</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecapsulateKeyDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey);

/// <summary>Initialize a signature-only verify operation, supplying the signature up front (PKCS#11 v3.2 §5.16.10). Data is fed via C_VerifySignature(Update) and the final check happens in C_VerifySignatureFinal.</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifySignatureInitDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen);

/// <summary>One-shot verify against the signature bound at init time (PKCS#11 v3.2 §5.16.11).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifySignatureDelegate(NativeCULong session, byte[] data, NativeCULong dataLen);

/// <summary>Feed a data chunk to a streaming signature-only verify (PKCS#11 v3.2 §5.16.12).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifySignatureUpdateDelegate(NativeCULong session, byte[] part, NativeCULong partLen);

/// <summary>Conclude a streaming signature-only verify; returns CKR_OK on match, CKR_SIGNATURE_INVALID otherwise (PKCS#11 v3.2 §5.16.13).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifySignatureFinalDelegate(NativeCULong session);

/// <summary>Reads the session's validation flags for the requested validation-state type (PKCS#11 v3.2 §5.6.10).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSessionValidationFlagsDelegate(NativeCULong session, NativeCULong type, ref NativeCULong flags);

/// <summary>Retrieve the result of a previously-pending async crypto operation (PKCS#11 v3.2 §5.20.2).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_AsyncCompleteDelegate(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result);

/// <summary>Obtain a persistent identifier for an async operation so it can be rejoined later (PKCS#11 v3.2 §5.20.3).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_AsyncGetIDDelegate(NativeCULong session, byte[] functionName, ref NativeCULong id);

/// <summary>Reattach to a previously-issued async operation using its persistent ID (PKCS#11 v3.2 §5.20.4).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_AsyncJoinDelegate(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen);

/// <summary>Wraps a key with authentication: the wrap is bound to the AAD bytes which must be supplied at unwrap (PKCS#11 v3.2 §5.18.12).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_WrapKeyAuthenticatedDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, [In, Out] byte[] wrappedKey, ref NativeCULong wrappedKeyLen);

/// <summary>Unwrap counterpart to C_WrapKeyAuthenticated; verifies the AAD as part of the unwrap (PKCS#11 v3.2 §5.18.13).</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_UnwrapKeyAuthenticatedDelegate(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key);

// ── Windows-layout variants ──────────────────────────────────────────────────
// Each delegate below is a platform-specific twin of the unified delegate above.
// Both target the SAME native function pointer; only the managed-side struct
// layout differs (Pack = 1 vs the platform default).  Used on Windows where the
// PKCS#11 ABI uses packed structs.

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetInfoDelegate_Windows(ref CK_INFO_Windows info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSlotInfoDelegate_Windows(NativeCULong slotId, ref CK_SLOT_INFO_Windows info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetTokenInfoDelegate_Windows(NativeCULong slotId, ref CK_TOKEN_INFO_Windows info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetMechanismInfoDelegate_Windows(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO_Windows info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GetSessionInfoDelegate_Windows(NativeCULong session, ref CK_SESSION_INFO_Windows info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncryptInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecryptInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DigestInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_SignRecoverInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifyRecoverInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, CK_ATTRIBUTE_Windows[] template, NativeCULong count, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_GenerateKeyPairDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, CK_ATTRIBUTE_Windows[] publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE_Windows[] privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_WrapKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong wrappingKey, NativeCULong key, [In, Out] byte[] wrappedKey, ref NativeCULong wrappedKeyLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_UnwrapKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DeriveKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong baseKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, ref NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageEncryptInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageDecryptInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageSignInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_MessageVerifyInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_EncapsulateKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong publicKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, [In, Out] byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_DecapsulateKeyDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong privateKey, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_VerifySignatureInitDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_AsyncCompleteDelegate_Windows(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA_Windows result);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_WrapKeyAuthenticatedDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, [In, Out] byte[] wrappedKey, ref NativeCULong wrappedKeyLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate NativeCULong C_UnwrapKeyAuthenticatedDelegate_Windows(NativeCULong session, ref CK_MECHANISM_Windows mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE_Windows[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key);

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
    private readonly FunctionPointers _fp = new();

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
        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeCULong C_GetFunctionList(out IntPtr functionList);
    }

    /// <summary>
    /// Delegate for C_Initialize
    /// </summary>
    internal C_InitializeDelegate? C_Initialize = null;

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
        if (_fp.C_GetInfo is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetInfo");
        fixed (CK_INFO* p = &info) return _fp.C_GetInfo(p);
    }

    /// <summary>
    /// Delegate for C_GetFunctionList
    /// </summary>
    internal C_GetFunctionListDelegate? C_GetFunctionList = null;

    /// <summary>
    /// Delegate for C_GetSlotList
    /// </summary>
    internal C_GetSlotListDelegate? C_GetSlotList = null;

    /// <summary>Wrapper for <c>C_GetSlotInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        if (_fp.C_GetSlotInfo is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSlotInfo");
        fixed (CK_SLOT_INFO* p = &info) return _fp.C_GetSlotInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetTokenInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        if (_fp.C_GetTokenInfo is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetTokenInfo");
        fixed (CK_TOKEN_INFO* p = &info) return _fp.C_GetTokenInfo(slotId, p);
    }

    /// <summary>
    /// Delegate for C_GetMechanismList
    /// </summary>
    internal C_GetMechanismListDelegate? C_GetMechanismList = null;

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
    {
        if (_fp.C_GetMechanismInfo is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetMechanismInfo");
        fixed (CK_MECHANISM_INFO* p = &info) return _fp.C_GetMechanismInfo(slotId, type, p);
    }

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
        if (_fp.C_GetSessionInfo is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_GetSessionInfo");
        fixed (CK_SESSION_INFO* p = &info) return _fp.C_GetSessionInfo(session, p);
    }

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

    /// <summary>Wrapper for <c>C_Logout</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Logout(NativeCULong session)
    {
        if (_fp.C_Logout is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_Logout");
        return _fp.C_Logout(session);
    }

    /// <summary>
    /// Delegate for C_CreateObject
    /// </summary>
    internal C_CreateObjectDelegate? C_CreateObject = null;

    /// <summary>
    /// Delegate for C_CopyObject
    /// </summary>
    internal C_CopyObjectDelegate? C_CopyObject = null;

    /// <summary>Wrapper for <c>C_DestroyObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        if (_fp.C_DestroyObject is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_DestroyObject");
        return _fp.C_DestroyObject(session, objectId);
    }

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

    /// <summary>Wrapper for <c>C_FindObjectsFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjectsFinal(NativeCULong session)
    {
        if (_fp.C_FindObjectsFinal is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_FindObjectsFinal");
        return _fp.C_FindObjectsFinal(session);
    }

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

    /// <summary>Wrapper for <c>C_CancelFunction</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CancelFunction(NativeCULong session)
    {
        if (_fp.C_CancelFunction is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_CancelFunction");
        return _fp.C_CancelFunction(session);
    }

    /// <summary>
    /// Delegate for C_WaitForSlotEvent
    /// </summary>
    internal C_WaitForSlotEventDelegate? C_WaitForSlotEvent = null;

    /// <summary>
    /// Delegate for C_LoginUser (PKCS#11 v3.0). Null if the loaded library is v2.40
    /// or does not export the symbol.
    /// </summary>
    internal C_LoginUserDelegate? C_LoginUser = null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SessionCancel</c> (PKCS#11 v3.0+).</summary>
    public unsafe bool IsC_SessionCancelSupported => _fp.C_SessionCancel is not null;

    /// <summary>Wrapper for <c>C_SessionCancel</c> (PKCS#11 v3.0). Throws <see cref="Pkcs11Exception"/> if the loaded library is v2.40 or does not export the symbol.</summary>
    public unsafe NativeCULong C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        if (_fp.C_SessionCancel is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, "C_SessionCancel");
        return _fp.C_SessionCancel(session, flags);
    }

    /// <summary>Delegate for C_MessageEncryptInit (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageEncryptInitDelegate? C_MessageEncryptInit = null;

    /// <summary>Delegate for C_EncryptMessage (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_EncryptMessageDelegate? C_EncryptMessage = null;

    /// <summary>Delegate for C_EncryptMessageBegin (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_EncryptMessageBeginDelegate? C_EncryptMessageBegin = null;

    /// <summary>Delegate for C_EncryptMessageNext (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_EncryptMessageNextDelegate? C_EncryptMessageNext = null;

    /// <summary>Delegate for C_MessageEncryptFinal (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageEncryptFinalDelegate? C_MessageEncryptFinal = null;

    /// <summary>Delegate for C_MessageDecryptInit (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageDecryptInitDelegate? C_MessageDecryptInit = null;

    /// <summary>Delegate for C_DecryptMessage (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_DecryptMessageDelegate? C_DecryptMessage = null;

    /// <summary>Delegate for C_DecryptMessageBegin (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_DecryptMessageBeginDelegate? C_DecryptMessageBegin = null;

    /// <summary>Delegate for C_DecryptMessageNext (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_DecryptMessageNextDelegate? C_DecryptMessageNext = null;

    /// <summary>Delegate for C_MessageDecryptFinal (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageDecryptFinalDelegate? C_MessageDecryptFinal = null;

    /// <summary>Delegate for C_MessageSignInit (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageSignInitDelegate? C_MessageSignInit = null;

    /// <summary>Delegate for C_SignMessage (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_SignMessageDelegate? C_SignMessage = null;

    /// <summary>Delegate for C_SignMessageBegin (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_SignMessageBeginDelegate? C_SignMessageBegin = null;

    /// <summary>Delegate for C_SignMessageNext (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_SignMessageNextDelegate? C_SignMessageNext = null;

    /// <summary>Delegate for C_MessageSignFinal (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageSignFinalDelegate? C_MessageSignFinal = null;

    /// <summary>Delegate for C_MessageVerifyInit (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageVerifyInitDelegate? C_MessageVerifyInit = null;

    /// <summary>Delegate for C_VerifyMessage (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_VerifyMessageDelegate? C_VerifyMessage = null;

    /// <summary>Delegate for C_VerifyMessageBegin (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_VerifyMessageBeginDelegate? C_VerifyMessageBegin = null;

    /// <summary>Delegate for C_VerifyMessageNext (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_VerifyMessageNextDelegate? C_VerifyMessageNext = null;

    /// <summary>Delegate for C_MessageVerifyFinal (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    internal C_MessageVerifyFinalDelegate? C_MessageVerifyFinal = null;

    /// <summary>Delegate for C_EncapsulateKey (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_EncapsulateKeyDelegate? C_EncapsulateKey = null;

    /// <summary>Delegate for C_DecapsulateKey (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_DecapsulateKeyDelegate? C_DecapsulateKey = null;

    /// <summary>Delegate for C_VerifySignatureInit (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_VerifySignatureInitDelegate? C_VerifySignatureInit = null;

    /// <summary>Delegate for C_VerifySignature (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_VerifySignatureDelegate? C_VerifySignature = null;

    /// <summary>Delegate for C_VerifySignatureUpdate (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_VerifySignatureUpdateDelegate? C_VerifySignatureUpdate = null;

    /// <summary>Delegate for C_VerifySignatureFinal (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_VerifySignatureFinalDelegate? C_VerifySignatureFinal = null;

    /// <summary>Delegate for C_GetSessionValidationFlags (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_GetSessionValidationFlagsDelegate? C_GetSessionValidationFlags = null;

    /// <summary>Delegate for C_AsyncComplete (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_AsyncCompleteDelegate? C_AsyncComplete = null;

    /// <summary>Delegate for C_AsyncGetID (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_AsyncGetIDDelegate? C_AsyncGetID = null;

    /// <summary>Delegate for C_AsyncJoin (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_AsyncJoinDelegate? C_AsyncJoin = null;

    /// <summary>Delegate for C_WrapKeyAuthenticated (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_WrapKeyAuthenticatedDelegate? C_WrapKeyAuthenticated = null;

    /// <summary>Delegate for C_UnwrapKeyAuthenticated (PKCS#11 v3.2). Null on libraries that do not expose it.</summary>
    internal C_UnwrapKeyAuthenticatedDelegate? C_UnwrapKeyAuthenticated = null;

    // ── Windows-layout delegate fields ───────────────────────────────────────
    // Populated from the same function pointer as their unified twin; used only
    // on Windows where packed struct layout is required.

    internal C_GetInfoDelegate_Windows? C_GetInfo_Windows;
    internal C_GetSlotInfoDelegate_Windows? C_GetSlotInfo_Windows;
    internal C_GetTokenInfoDelegate_Windows? C_GetTokenInfo_Windows;
    internal C_GetMechanismInfoDelegate_Windows? C_GetMechanismInfo_Windows;
    internal C_GetSessionInfoDelegate_Windows? C_GetSessionInfo_Windows;
    internal C_EncryptInitDelegate_Windows? C_EncryptInit_Windows;
    internal C_DecryptInitDelegate_Windows? C_DecryptInit_Windows;
    internal C_DigestInitDelegate_Windows? C_DigestInit_Windows;
    internal C_SignInitDelegate_Windows? C_SignInit_Windows;
    internal C_SignRecoverInitDelegate_Windows? C_SignRecoverInit_Windows;
    internal C_VerifyInitDelegate_Windows? C_VerifyInit_Windows;
    internal C_VerifyRecoverInitDelegate_Windows? C_VerifyRecoverInit_Windows;
    internal C_GenerateKeyDelegate_Windows? C_GenerateKey_Windows;
    internal C_GenerateKeyPairDelegate_Windows? C_GenerateKeyPair_Windows;
    internal C_WrapKeyDelegate_Windows? C_WrapKey_Windows;
    internal C_UnwrapKeyDelegate_Windows? C_UnwrapKey_Windows;
    internal C_DeriveKeyDelegate_Windows? C_DeriveKey_Windows;
    internal C_MessageEncryptInitDelegate_Windows? C_MessageEncryptInit_Windows;
    internal C_MessageDecryptInitDelegate_Windows? C_MessageDecryptInit_Windows;
    internal C_MessageSignInitDelegate_Windows? C_MessageSignInit_Windows;
    internal C_MessageVerifyInitDelegate_Windows? C_MessageVerifyInit_Windows;
    internal C_EncapsulateKeyDelegate_Windows? C_EncapsulateKey_Windows;
    internal C_DecapsulateKeyDelegate_Windows? C_DecapsulateKey_Windows;
    internal C_VerifySignatureInitDelegate_Windows? C_VerifySignatureInit_Windows;
    internal C_AsyncCompleteDelegate_Windows? C_AsyncComplete_Windows;
    internal C_WrapKeyAuthenticatedDelegate_Windows? C_WrapKeyAuthenticated_Windows;
    internal C_UnwrapKeyAuthenticatedDelegate_Windows? C_UnwrapKeyAuthenticated_Windows;
    internal C_CreateObjectDelegate_Windows? C_CreateObject_Windows;
    internal C_CopyObjectDelegate_Windows? C_CopyObject_Windows;
    internal C_GetAttributeValueDelegate_Windows? C_GetAttributeValue_Windows;
    internal C_SetAttributeValueDelegate_Windows? C_SetAttributeValue_Windows;
    internal C_FindObjectsInitDelegate_Windows? C_FindObjectsInit_Windows;

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
        C_LoginUser = TryGetDelegate<C_LoginUserDelegate>(libraryHandle, "C_LoginUser");
        if (NativeLibrary.TryGetExport(libraryHandle, "C_SessionCancel", out IntPtr sessionCancelPtr) && sessionCancelPtr != IntPtr.Zero)
            unsafe { _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)sessionCancelPtr; }
        C_MessageEncryptInit = TryGetDelegate<C_MessageEncryptInitDelegate>(libraryHandle, "C_MessageEncryptInit");
        C_MessageEncryptInit_Windows = TryGetDelegate<C_MessageEncryptInitDelegate_Windows>(libraryHandle, "C_MessageEncryptInit");
        C_EncryptMessage = TryGetDelegate<C_EncryptMessageDelegate>(libraryHandle, "C_EncryptMessage");
        C_EncryptMessageBegin = TryGetDelegate<C_EncryptMessageBeginDelegate>(libraryHandle, "C_EncryptMessageBegin");
        C_EncryptMessageNext = TryGetDelegate<C_EncryptMessageNextDelegate>(libraryHandle, "C_EncryptMessageNext");
        C_MessageEncryptFinal = TryGetDelegate<C_MessageEncryptFinalDelegate>(libraryHandle, "C_MessageEncryptFinal");
        C_MessageDecryptInit = TryGetDelegate<C_MessageDecryptInitDelegate>(libraryHandle, "C_MessageDecryptInit");
        C_MessageDecryptInit_Windows = TryGetDelegate<C_MessageDecryptInitDelegate_Windows>(libraryHandle, "C_MessageDecryptInit");
        C_DecryptMessage = TryGetDelegate<C_DecryptMessageDelegate>(libraryHandle, "C_DecryptMessage");
        C_DecryptMessageBegin = TryGetDelegate<C_DecryptMessageBeginDelegate>(libraryHandle, "C_DecryptMessageBegin");
        C_DecryptMessageNext = TryGetDelegate<C_DecryptMessageNextDelegate>(libraryHandle, "C_DecryptMessageNext");
        C_MessageDecryptFinal = TryGetDelegate<C_MessageDecryptFinalDelegate>(libraryHandle, "C_MessageDecryptFinal");
        C_MessageSignInit = TryGetDelegate<C_MessageSignInitDelegate>(libraryHandle, "C_MessageSignInit");
        C_MessageSignInit_Windows = TryGetDelegate<C_MessageSignInitDelegate_Windows>(libraryHandle, "C_MessageSignInit");
        C_SignMessage = TryGetDelegate<C_SignMessageDelegate>(libraryHandle, "C_SignMessage");
        C_SignMessageBegin = TryGetDelegate<C_SignMessageBeginDelegate>(libraryHandle, "C_SignMessageBegin");
        C_SignMessageNext = TryGetDelegate<C_SignMessageNextDelegate>(libraryHandle, "C_SignMessageNext");
        C_MessageSignFinal = TryGetDelegate<C_MessageSignFinalDelegate>(libraryHandle, "C_MessageSignFinal");
        C_MessageVerifyInit = TryGetDelegate<C_MessageVerifyInitDelegate>(libraryHandle, "C_MessageVerifyInit");
        C_MessageVerifyInit_Windows = TryGetDelegate<C_MessageVerifyInitDelegate_Windows>(libraryHandle, "C_MessageVerifyInit");
        C_VerifyMessage = TryGetDelegate<C_VerifyMessageDelegate>(libraryHandle, "C_VerifyMessage");
        C_VerifyMessageBegin = TryGetDelegate<C_VerifyMessageBeginDelegate>(libraryHandle, "C_VerifyMessageBegin");
        C_VerifyMessageNext = TryGetDelegate<C_VerifyMessageNextDelegate>(libraryHandle, "C_VerifyMessageNext");
        C_MessageVerifyFinal = TryGetDelegate<C_MessageVerifyFinalDelegate>(libraryHandle, "C_MessageVerifyFinal");
        C_EncapsulateKey = TryGetDelegate<C_EncapsulateKeyDelegate>(libraryHandle, "C_EncapsulateKey");
        C_EncapsulateKey_Windows = TryGetDelegate<C_EncapsulateKeyDelegate_Windows>(libraryHandle, "C_EncapsulateKey");
        C_DecapsulateKey = TryGetDelegate<C_DecapsulateKeyDelegate>(libraryHandle, "C_DecapsulateKey");
        C_DecapsulateKey_Windows = TryGetDelegate<C_DecapsulateKeyDelegate_Windows>(libraryHandle, "C_DecapsulateKey");
        C_VerifySignatureInit = TryGetDelegate<C_VerifySignatureInitDelegate>(libraryHandle, "C_VerifySignatureInit");
        C_VerifySignatureInit_Windows = TryGetDelegate<C_VerifySignatureInitDelegate_Windows>(libraryHandle, "C_VerifySignatureInit");
        C_VerifySignature = TryGetDelegate<C_VerifySignatureDelegate>(libraryHandle, "C_VerifySignature");
        C_VerifySignatureUpdate = TryGetDelegate<C_VerifySignatureUpdateDelegate>(libraryHandle, "C_VerifySignatureUpdate");
        C_VerifySignatureFinal = TryGetDelegate<C_VerifySignatureFinalDelegate>(libraryHandle, "C_VerifySignatureFinal");
        C_GetSessionValidationFlags = TryGetDelegate<C_GetSessionValidationFlagsDelegate>(libraryHandle, "C_GetSessionValidationFlags");
        C_AsyncComplete = TryGetDelegate<C_AsyncCompleteDelegate>(libraryHandle, "C_AsyncComplete");
        C_AsyncComplete_Windows = TryGetDelegate<C_AsyncCompleteDelegate_Windows>(libraryHandle, "C_AsyncComplete");
        C_AsyncGetID = TryGetDelegate<C_AsyncGetIDDelegate>(libraryHandle, "C_AsyncGetID");
        C_AsyncJoin = TryGetDelegate<C_AsyncJoinDelegate>(libraryHandle, "C_AsyncJoin");
        C_WrapKeyAuthenticated = TryGetDelegate<C_WrapKeyAuthenticatedDelegate>(libraryHandle, "C_WrapKeyAuthenticated");
        C_WrapKeyAuthenticated_Windows = TryGetDelegate<C_WrapKeyAuthenticatedDelegate_Windows>(libraryHandle, "C_WrapKeyAuthenticated");
        C_UnwrapKeyAuthenticated = TryGetDelegate<C_UnwrapKeyAuthenticatedDelegate>(libraryHandle, "C_UnwrapKeyAuthenticated");
        C_UnwrapKeyAuthenticated_Windows = TryGetDelegate<C_UnwrapKeyAuthenticatedDelegate_Windows>(libraryHandle, "C_UnwrapKeyAuthenticated");
    }

    private static T? TryGetDelegate<T>(IntPtr libraryHandle, string symbol) where T : class
    {
        if (NativeLibrary.TryGetExport(libraryHandle, symbol, out IntPtr fnPtr) && fnPtr != IntPtr.Zero)
            return Marshal.GetDelegateForFunctionPointer<T>(fnPtr);
        return null;
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
        var getInterface = TryGetDelegate<C_GetInterfaceDelegate>(libraryHandle, "C_GetInterface");
        if (getInterface is null) return false;

        // Request the default interface: null name, null version, flags = 0.
        IntPtr interfacePtr;
        NativeCULong rv;
        try
        {
            rv = getInterface(null, IntPtr.Zero, out interfacePtr, new NativeCULong(0));
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
        if (version.Major is null || version.Major.Length == 0 || version.Major[0] < 3) return false;

        CK_FUNCTION_LIST_3_0 v30 = UnmanagedMemory.Read<CK_FUNCTION_LIST_3_0>(iface.FunctionList);

        if (v30.C_LoginUser != IntPtr.Zero)
            C_LoginUser = Marshal.GetDelegateForFunctionPointer<C_LoginUserDelegate>(v30.C_LoginUser);
        if (v30.C_SessionCancel != IntPtr.Zero)
            unsafe { _fp.C_SessionCancel = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)v30.C_SessionCancel; }

        if (v30.C_MessageEncryptInit != IntPtr.Zero)
        {
            C_MessageEncryptInit = Marshal.GetDelegateForFunctionPointer<C_MessageEncryptInitDelegate>(v30.C_MessageEncryptInit);
            C_MessageEncryptInit_Windows = Marshal.GetDelegateForFunctionPointer<C_MessageEncryptInitDelegate_Windows>(v30.C_MessageEncryptInit);
        }
        if (v30.C_EncryptMessage != IntPtr.Zero)
            C_EncryptMessage = Marshal.GetDelegateForFunctionPointer<C_EncryptMessageDelegate>(v30.C_EncryptMessage);
        if (v30.C_EncryptMessageBegin != IntPtr.Zero)
            C_EncryptMessageBegin = Marshal.GetDelegateForFunctionPointer<C_EncryptMessageBeginDelegate>(v30.C_EncryptMessageBegin);
        if (v30.C_EncryptMessageNext != IntPtr.Zero)
            C_EncryptMessageNext = Marshal.GetDelegateForFunctionPointer<C_EncryptMessageNextDelegate>(v30.C_EncryptMessageNext);
        if (v30.C_MessageEncryptFinal != IntPtr.Zero)
            C_MessageEncryptFinal = Marshal.GetDelegateForFunctionPointer<C_MessageEncryptFinalDelegate>(v30.C_MessageEncryptFinal);

        if (v30.C_MessageDecryptInit != IntPtr.Zero)
        {
            C_MessageDecryptInit = Marshal.GetDelegateForFunctionPointer<C_MessageDecryptInitDelegate>(v30.C_MessageDecryptInit);
            C_MessageDecryptInit_Windows = Marshal.GetDelegateForFunctionPointer<C_MessageDecryptInitDelegate_Windows>(v30.C_MessageDecryptInit);
        }
        if (v30.C_DecryptMessage != IntPtr.Zero)
            C_DecryptMessage = Marshal.GetDelegateForFunctionPointer<C_DecryptMessageDelegate>(v30.C_DecryptMessage);
        if (v30.C_DecryptMessageBegin != IntPtr.Zero)
            C_DecryptMessageBegin = Marshal.GetDelegateForFunctionPointer<C_DecryptMessageBeginDelegate>(v30.C_DecryptMessageBegin);
        if (v30.C_DecryptMessageNext != IntPtr.Zero)
            C_DecryptMessageNext = Marshal.GetDelegateForFunctionPointer<C_DecryptMessageNextDelegate>(v30.C_DecryptMessageNext);
        if (v30.C_MessageDecryptFinal != IntPtr.Zero)
            C_MessageDecryptFinal = Marshal.GetDelegateForFunctionPointer<C_MessageDecryptFinalDelegate>(v30.C_MessageDecryptFinal);

        if (v30.C_MessageSignInit != IntPtr.Zero)
        {
            C_MessageSignInit = Marshal.GetDelegateForFunctionPointer<C_MessageSignInitDelegate>(v30.C_MessageSignInit);
            C_MessageSignInit_Windows = Marshal.GetDelegateForFunctionPointer<C_MessageSignInitDelegate_Windows>(v30.C_MessageSignInit);
        }
        if (v30.C_SignMessage != IntPtr.Zero)
            C_SignMessage = Marshal.GetDelegateForFunctionPointer<C_SignMessageDelegate>(v30.C_SignMessage);
        if (v30.C_SignMessageBegin != IntPtr.Zero)
            C_SignMessageBegin = Marshal.GetDelegateForFunctionPointer<C_SignMessageBeginDelegate>(v30.C_SignMessageBegin);
        if (v30.C_SignMessageNext != IntPtr.Zero)
            C_SignMessageNext = Marshal.GetDelegateForFunctionPointer<C_SignMessageNextDelegate>(v30.C_SignMessageNext);
        if (v30.C_MessageSignFinal != IntPtr.Zero)
            C_MessageSignFinal = Marshal.GetDelegateForFunctionPointer<C_MessageSignFinalDelegate>(v30.C_MessageSignFinal);

        if (v30.C_MessageVerifyInit != IntPtr.Zero)
        {
            C_MessageVerifyInit = Marshal.GetDelegateForFunctionPointer<C_MessageVerifyInitDelegate>(v30.C_MessageVerifyInit);
            C_MessageVerifyInit_Windows = Marshal.GetDelegateForFunctionPointer<C_MessageVerifyInitDelegate_Windows>(v30.C_MessageVerifyInit);
        }
        if (v30.C_VerifyMessage != IntPtr.Zero)
            C_VerifyMessage = Marshal.GetDelegateForFunctionPointer<C_VerifyMessageDelegate>(v30.C_VerifyMessage);
        if (v30.C_VerifyMessageBegin != IntPtr.Zero)
            C_VerifyMessageBegin = Marshal.GetDelegateForFunctionPointer<C_VerifyMessageBeginDelegate>(v30.C_VerifyMessageBegin);
        if (v30.C_VerifyMessageNext != IntPtr.Zero)
            C_VerifyMessageNext = Marshal.GetDelegateForFunctionPointer<C_VerifyMessageNextDelegate>(v30.C_VerifyMessageNext);
        if (v30.C_MessageVerifyFinal != IntPtr.Zero)
            C_MessageVerifyFinal = Marshal.GetDelegateForFunctionPointer<C_MessageVerifyFinalDelegate>(v30.C_MessageVerifyFinal);

        // v3.2 token: re-read the function table as CK_FUNCTION_LIST_3_2 and bind
        // the 12 v3.2 additions on top of the v3.0 bindings.
        if (version.Minor is not null && version.Minor.Length > 0 && version.Minor[0] >= 2)
        {
            CK_FUNCTION_LIST_3_2 v32 = UnmanagedMemory.Read<CK_FUNCTION_LIST_3_2>(iface.FunctionList);

            if (v32.C_EncapsulateKey != IntPtr.Zero)
            {
                C_EncapsulateKey = Marshal.GetDelegateForFunctionPointer<C_EncapsulateKeyDelegate>(v32.C_EncapsulateKey);
                C_EncapsulateKey_Windows = Marshal.GetDelegateForFunctionPointer<C_EncapsulateKeyDelegate_Windows>(v32.C_EncapsulateKey);
            }
            if (v32.C_DecapsulateKey != IntPtr.Zero)
            {
                C_DecapsulateKey = Marshal.GetDelegateForFunctionPointer<C_DecapsulateKeyDelegate>(v32.C_DecapsulateKey);
                C_DecapsulateKey_Windows = Marshal.GetDelegateForFunctionPointer<C_DecapsulateKeyDelegate_Windows>(v32.C_DecapsulateKey);
            }
            if (v32.C_VerifySignatureInit != IntPtr.Zero)
            {
                C_VerifySignatureInit = Marshal.GetDelegateForFunctionPointer<C_VerifySignatureInitDelegate>(v32.C_VerifySignatureInit);
                C_VerifySignatureInit_Windows = Marshal.GetDelegateForFunctionPointer<C_VerifySignatureInitDelegate_Windows>(v32.C_VerifySignatureInit);
            }
            if (v32.C_VerifySignature != IntPtr.Zero)
                C_VerifySignature = Marshal.GetDelegateForFunctionPointer<C_VerifySignatureDelegate>(v32.C_VerifySignature);
            if (v32.C_VerifySignatureUpdate != IntPtr.Zero)
                C_VerifySignatureUpdate = Marshal.GetDelegateForFunctionPointer<C_VerifySignatureUpdateDelegate>(v32.C_VerifySignatureUpdate);
            if (v32.C_VerifySignatureFinal != IntPtr.Zero)
                C_VerifySignatureFinal = Marshal.GetDelegateForFunctionPointer<C_VerifySignatureFinalDelegate>(v32.C_VerifySignatureFinal);
            if (v32.C_GetSessionValidationFlags != IntPtr.Zero)
                C_GetSessionValidationFlags = Marshal.GetDelegateForFunctionPointer<C_GetSessionValidationFlagsDelegate>(v32.C_GetSessionValidationFlags);
            if (v32.C_AsyncComplete != IntPtr.Zero)
            {
                C_AsyncComplete = Marshal.GetDelegateForFunctionPointer<C_AsyncCompleteDelegate>(v32.C_AsyncComplete);
                C_AsyncComplete_Windows = Marshal.GetDelegateForFunctionPointer<C_AsyncCompleteDelegate_Windows>(v32.C_AsyncComplete);
            }
            if (v32.C_AsyncGetID != IntPtr.Zero)
                C_AsyncGetID = Marshal.GetDelegateForFunctionPointer<C_AsyncGetIDDelegate>(v32.C_AsyncGetID);
            if (v32.C_AsyncJoin != IntPtr.Zero)
                C_AsyncJoin = Marshal.GetDelegateForFunctionPointer<C_AsyncJoinDelegate>(v32.C_AsyncJoin);
            if (v32.C_WrapKeyAuthenticated != IntPtr.Zero)
            {
                C_WrapKeyAuthenticated = Marshal.GetDelegateForFunctionPointer<C_WrapKeyAuthenticatedDelegate>(v32.C_WrapKeyAuthenticated);
                C_WrapKeyAuthenticated_Windows = Marshal.GetDelegateForFunctionPointer<C_WrapKeyAuthenticatedDelegate_Windows>(v32.C_WrapKeyAuthenticated);
            }
            if (v32.C_UnwrapKeyAuthenticated != IntPtr.Zero)
            {
                C_UnwrapKeyAuthenticated = Marshal.GetDelegateForFunctionPointer<C_UnwrapKeyAuthenticatedDelegate>(v32.C_UnwrapKeyAuthenticated);
                C_UnwrapKeyAuthenticated_Windows = Marshal.GetDelegateForFunctionPointer<C_UnwrapKeyAuthenticatedDelegate_Windows>(v32.C_UnwrapKeyAuthenticated);
            }
        }

        return true;
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

        CK_FUNCTION_LIST funcList = UnmanagedMemory.Read<CK_FUNCTION_LIST>(functionList);
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

        CK_FUNCTION_LIST funcList = UnmanagedMemory.Read<CK_FUNCTION_LIST>(functionList);
        Initialize(funcList);
    }


    /// <summary>
    /// Get delegates from unmanaged function pointers
    /// </summary>
    /// <param name="funcList">Structure which contains cryptoki function pointers</param>
    private void Initialize(CK_FUNCTION_LIST funcList)
    {
        C_Initialize = Marshal.GetDelegateForFunctionPointer<C_InitializeDelegate>(funcList.C_Initialize);
        unsafe { _fp.C_Finalize = (delegate* unmanaged[Cdecl]<IntPtr, NativeCULong>)funcList.C_Finalize; }
        unsafe { _fp.C_GetInfo = (delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong>)funcList.C_GetInfo; }
        C_GetInfo_Windows = Marshal.GetDelegateForFunctionPointer<C_GetInfoDelegate_Windows>(funcList.C_GetInfo);
        C_GetFunctionList = Marshal.GetDelegateForFunctionPointer<C_GetFunctionListDelegate>(funcList.C_GetFunctionList);
        C_GetSlotList = Marshal.GetDelegateForFunctionPointer<C_GetSlotListDelegate>(funcList.C_GetSlotList);
        unsafe { _fp.C_GetSlotInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO*, NativeCULong>)funcList.C_GetSlotInfo; }
        C_GetSlotInfo_Windows = Marshal.GetDelegateForFunctionPointer<C_GetSlotInfoDelegate_Windows>(funcList.C_GetSlotInfo);
        unsafe { _fp.C_GetTokenInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO*, NativeCULong>)funcList.C_GetTokenInfo; }
        C_GetTokenInfo_Windows = Marshal.GetDelegateForFunctionPointer<C_GetTokenInfoDelegate_Windows>(funcList.C_GetTokenInfo);
        C_GetMechanismList = Marshal.GetDelegateForFunctionPointer<C_GetMechanismListDelegate>(funcList.C_GetMechanismList);
        unsafe { _fp.C_GetMechanismInfo = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong>)funcList.C_GetMechanismInfo; }
        C_GetMechanismInfo_Windows = Marshal.GetDelegateForFunctionPointer<C_GetMechanismInfoDelegate_Windows>(funcList.C_GetMechanismInfo);
        C_InitToken = Marshal.GetDelegateForFunctionPointer<C_InitTokenDelegate>(funcList.C_InitToken);
        C_InitPIN = Marshal.GetDelegateForFunctionPointer<C_InitPINDelegate>(funcList.C_InitPIN);
        C_SetPIN = Marshal.GetDelegateForFunctionPointer<C_SetPINDelegate>(funcList.C_SetPIN);
        C_OpenSession = Marshal.GetDelegateForFunctionPointer<C_OpenSessionDelegate>(funcList.C_OpenSession);
        unsafe { _fp.C_CloseSession = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CloseSession; }
        unsafe { _fp.C_CloseAllSessions = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CloseAllSessions; }
        unsafe { _fp.C_GetSessionInfo = (delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong>)funcList.C_GetSessionInfo; }
        C_GetSessionInfo_Windows = Marshal.GetDelegateForFunctionPointer<C_GetSessionInfoDelegate_Windows>(funcList.C_GetSessionInfo);
        C_GetOperationState = Marshal.GetDelegateForFunctionPointer<C_GetOperationStateDelegate>(funcList.C_GetOperationState);
        C_SetOperationState = Marshal.GetDelegateForFunctionPointer<C_SetOperationStateDelegate>(funcList.C_SetOperationState);
        C_Login = Marshal.GetDelegateForFunctionPointer<C_LoginDelegate>(funcList.C_Login);
        unsafe { _fp.C_Logout = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_Logout; }
        C_CreateObject = Marshal.GetDelegateForFunctionPointer<C_CreateObjectDelegate>(funcList.C_CreateObject);
        C_CreateObject_Windows = Marshal.GetDelegateForFunctionPointer<C_CreateObjectDelegate_Windows>(funcList.C_CreateObject);
        C_CopyObject = Marshal.GetDelegateForFunctionPointer<C_CopyObjectDelegate>(funcList.C_CopyObject);
        C_CopyObject_Windows = Marshal.GetDelegateForFunctionPointer<C_CopyObjectDelegate_Windows>(funcList.C_CopyObject);
        unsafe { _fp.C_DestroyObject = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)funcList.C_DestroyObject; }
        C_GetObjectSize = Marshal.GetDelegateForFunctionPointer<C_GetObjectSizeDelegate>(funcList.C_GetObjectSize);
        C_GetAttributeValue = Marshal.GetDelegateForFunctionPointer<C_GetAttributeValueDelegate>(funcList.C_GetAttributeValue);
        C_GetAttributeValue_Windows = Marshal.GetDelegateForFunctionPointer<C_GetAttributeValueDelegate_Windows>(funcList.C_GetAttributeValue);
        C_SetAttributeValue = Marshal.GetDelegateForFunctionPointer<C_SetAttributeValueDelegate>(funcList.C_SetAttributeValue);
        C_SetAttributeValue_Windows = Marshal.GetDelegateForFunctionPointer<C_SetAttributeValueDelegate_Windows>(funcList.C_SetAttributeValue);
        C_FindObjectsInit = Marshal.GetDelegateForFunctionPointer<C_FindObjectsInitDelegate>(funcList.C_FindObjectsInit);
        C_FindObjectsInit_Windows = Marshal.GetDelegateForFunctionPointer<C_FindObjectsInitDelegate_Windows>(funcList.C_FindObjectsInit);
        C_FindObjects = Marshal.GetDelegateForFunctionPointer<C_FindObjectsDelegate>(funcList.C_FindObjects);
        unsafe { _fp.C_FindObjectsFinal = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_FindObjectsFinal; }
        C_EncryptInit = Marshal.GetDelegateForFunctionPointer<C_EncryptInitDelegate>(funcList.C_EncryptInit);
        C_EncryptInit_Windows = Marshal.GetDelegateForFunctionPointer<C_EncryptInitDelegate_Windows>(funcList.C_EncryptInit);
        C_Encrypt = Marshal.GetDelegateForFunctionPointer<C_EncryptDelegate>(funcList.C_Encrypt);
        C_EncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_EncryptUpdateDelegate>(funcList.C_EncryptUpdate);
        C_EncryptFinal = Marshal.GetDelegateForFunctionPointer<C_EncryptFinalDelegate>(funcList.C_EncryptFinal);
        C_DecryptInit = Marshal.GetDelegateForFunctionPointer<C_DecryptInitDelegate>(funcList.C_DecryptInit);
        C_DecryptInit_Windows = Marshal.GetDelegateForFunctionPointer<C_DecryptInitDelegate_Windows>(funcList.C_DecryptInit);
        C_Decrypt = Marshal.GetDelegateForFunctionPointer<C_DecryptDelegate>(funcList.C_Decrypt);
        C_DecryptUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptUpdateDelegate>(funcList.C_DecryptUpdate);
        C_DecryptFinal = Marshal.GetDelegateForFunctionPointer<C_DecryptFinalDelegate>(funcList.C_DecryptFinal);
        C_DigestInit = Marshal.GetDelegateForFunctionPointer<C_DigestInitDelegate>(funcList.C_DigestInit);
        C_DigestInit_Windows = Marshal.GetDelegateForFunctionPointer<C_DigestInitDelegate_Windows>(funcList.C_DigestInit);
        C_Digest = Marshal.GetDelegateForFunctionPointer<C_DigestDelegate>(funcList.C_Digest);
        C_DigestUpdate = Marshal.GetDelegateForFunctionPointer<C_DigestUpdateDelegate>(funcList.C_DigestUpdate);
        C_DigestKey = Marshal.GetDelegateForFunctionPointer<C_DigestKeyDelegate>(funcList.C_DigestKey);
        C_DigestFinal = Marshal.GetDelegateForFunctionPointer<C_DigestFinalDelegate>(funcList.C_DigestFinal);
        C_SignInit = Marshal.GetDelegateForFunctionPointer<C_SignInitDelegate>(funcList.C_SignInit);
        C_SignInit_Windows = Marshal.GetDelegateForFunctionPointer<C_SignInitDelegate_Windows>(funcList.C_SignInit);
        C_Sign = Marshal.GetDelegateForFunctionPointer<C_SignDelegate>(funcList.C_Sign);
        C_SignUpdate = Marshal.GetDelegateForFunctionPointer<C_SignUpdateDelegate>(funcList.C_SignUpdate);
        C_SignFinal = Marshal.GetDelegateForFunctionPointer<C_SignFinalDelegate>(funcList.C_SignFinal);
        C_SignRecoverInit = Marshal.GetDelegateForFunctionPointer<C_SignRecoverInitDelegate>(funcList.C_SignRecoverInit);
        C_SignRecoverInit_Windows = Marshal.GetDelegateForFunctionPointer<C_SignRecoverInitDelegate_Windows>(funcList.C_SignRecoverInit);
        C_SignRecover = Marshal.GetDelegateForFunctionPointer<C_SignRecoverDelegate>(funcList.C_SignRecover);
        C_VerifyInit = Marshal.GetDelegateForFunctionPointer<C_VerifyInitDelegate>(funcList.C_VerifyInit);
        C_VerifyInit_Windows = Marshal.GetDelegateForFunctionPointer<C_VerifyInitDelegate_Windows>(funcList.C_VerifyInit);
        C_Verify = Marshal.GetDelegateForFunctionPointer<C_VerifyDelegate>(funcList.C_Verify);
        C_VerifyUpdate = Marshal.GetDelegateForFunctionPointer<C_VerifyUpdateDelegate>(funcList.C_VerifyUpdate);
        C_VerifyFinal = Marshal.GetDelegateForFunctionPointer<C_VerifyFinalDelegate>(funcList.C_VerifyFinal);
        C_VerifyRecoverInit = Marshal.GetDelegateForFunctionPointer<C_VerifyRecoverInitDelegate>(funcList.C_VerifyRecoverInit);
        C_VerifyRecoverInit_Windows = Marshal.GetDelegateForFunctionPointer<C_VerifyRecoverInitDelegate_Windows>(funcList.C_VerifyRecoverInit);
        C_VerifyRecover = Marshal.GetDelegateForFunctionPointer<C_VerifyRecoverDelegate>(funcList.C_VerifyRecover);
        C_DigestEncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_DigestEncryptUpdateDelegate>(funcList.C_DigestEncryptUpdate);
        C_DecryptDigestUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptDigestUpdateDelegate>(funcList.C_DecryptDigestUpdate);
        C_SignEncryptUpdate = Marshal.GetDelegateForFunctionPointer<C_SignEncryptUpdateDelegate>(funcList.C_SignEncryptUpdate);
        C_DecryptVerifyUpdate = Marshal.GetDelegateForFunctionPointer<C_DecryptVerifyUpdateDelegate>(funcList.C_DecryptVerifyUpdate);
        C_GenerateKey = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyDelegate>(funcList.C_GenerateKey);
        C_GenerateKey_Windows = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyDelegate_Windows>(funcList.C_GenerateKey);
        C_GenerateKeyPair = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyPairDelegate>(funcList.C_GenerateKeyPair);
        C_GenerateKeyPair_Windows = Marshal.GetDelegateForFunctionPointer<C_GenerateKeyPairDelegate_Windows>(funcList.C_GenerateKeyPair);
        C_WrapKey = Marshal.GetDelegateForFunctionPointer<C_WrapKeyDelegate>(funcList.C_WrapKey);
        C_WrapKey_Windows = Marshal.GetDelegateForFunctionPointer<C_WrapKeyDelegate_Windows>(funcList.C_WrapKey);
        C_UnwrapKey = Marshal.GetDelegateForFunctionPointer<C_UnwrapKeyDelegate>(funcList.C_UnwrapKey);
        C_UnwrapKey_Windows = Marshal.GetDelegateForFunctionPointer<C_UnwrapKeyDelegate_Windows>(funcList.C_UnwrapKey);
        C_DeriveKey = Marshal.GetDelegateForFunctionPointer<C_DeriveKeyDelegate>(funcList.C_DeriveKey);
        C_DeriveKey_Windows = Marshal.GetDelegateForFunctionPointer<C_DeriveKeyDelegate_Windows>(funcList.C_DeriveKey);
        C_SeedRandom = Marshal.GetDelegateForFunctionPointer<C_SeedRandomDelegate>(funcList.C_SeedRandom);
        C_GenerateRandom = Marshal.GetDelegateForFunctionPointer<C_GenerateRandomDelegate>(funcList.C_GenerateRandom);
        C_GetFunctionStatus = Marshal.GetDelegateForFunctionPointer<C_GetFunctionStatusDelegate>(funcList.C_GetFunctionStatus);
        unsafe { _fp.C_CancelFunction = (delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)funcList.C_CancelFunction; }
        C_WaitForSlotEvent = Marshal.GetDelegateForFunctionPointer<C_WaitForSlotEventDelegate>(funcList.C_WaitForSlotEvent);
    }
}