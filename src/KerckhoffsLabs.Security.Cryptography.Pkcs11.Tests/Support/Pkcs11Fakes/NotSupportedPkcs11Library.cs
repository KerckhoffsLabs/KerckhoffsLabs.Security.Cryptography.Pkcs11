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
    public virtual CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CloseSession(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CloseAllSessions(NativeCULong slotId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetOperationState(NativeCULong session, Span<byte> operationState, out NativeCULong operationStateLen) { operationStateLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey, NativeCULong authenticationKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Login(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_LoginUser(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface) { iface = default; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out NativeCULong ciphertextLen) { ciphertextLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, out NativeCULong ciphertextPartLen, NativeCULong flags) { ciphertextPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_MessageEncryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out NativeCULong plaintextLen) { plaintextLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, out NativeCULong plaintextPartLen, NativeCULong flags) { plaintextPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen) { signatureLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen) { signatureLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_MessageSignFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_MessageVerifyFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, ReadOnlySpan<CK_ATTRIBUTE> template, Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey) { ciphertextLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifySignatureFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen) { wrappedKeyLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Logout(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong newObjectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, out NativeCULong encryptedDataLen) { encryptedDataLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen) { encryptedPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, out NativeCULong lastEncryptedPartLen) { lastEncryptedPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen) { dataLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen) { partLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptFinal(NativeCULong session, Span<byte> lastPart, out NativeCULong lastPartLen) { lastPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, out NativeCULong digestLen) { digestLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestKey(NativeCULong session, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DigestFinal(NativeCULong session, Span<byte> digest, out NativeCULong digestLen) { digestLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen) { signatureLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignFinal(NativeCULong session, Span<byte> signature, out NativeCULong signatureLen) { signatureLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen) { signatureLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, out NativeCULong dataLen) { dataLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen) { encryptedPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen) { partLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen) { encryptedPartLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen) { partLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate, ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen) { wrappedKeyLen = (NativeCULong)0; return CKR.CKR_FUNCTION_NOT_SUPPORTED; }
    public virtual CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_GetFunctionStatus(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_CancelFunction(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    public virtual CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
}
