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
    protected virtual CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignFinal(NativeCULong session, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, NativeBuffer<byte> data, ref NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifySignatureInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifySignatureFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DigestKey(NativeCULong session, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> ciphertext, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_WrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, ReadOnlySpan<byte> associatedData, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_UnwrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> associatedData, ref NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetFunctionStatus(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_CancelFunction(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, ref NativeCULong newObjectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_CloseAllSessions(NativeCULong slotId) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetOperationState(NativeCULong session, NativeBuffer<byte> operationState, ref NativeCULong operationStateLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey, NativeCULong authenticationKey) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetMechanismList(NativeCULong slotId, NativeBuffer<NativeCULong> mechanismList, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageEncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart, NativeBuffer<byte> ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageEncryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart, NativeBuffer<byte> plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageSignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageSignFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageVerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_MessageVerifyFinal(NativeCULong session) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_AsyncComplete(NativeCULong session, string functionName, ref CK_ASYNC_DATA result) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_AsyncGetID(NativeCULong session, string functionName, ref NativeCULong id) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_AsyncJoin(NativeCULong session, string functionName, NativeCULong id, ReadOnlySpan<byte> data) => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    protected virtual CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData) => CKR.CKR_FUNCTION_NOT_SUPPORTED;

    private void BindFunctions(Dictionary<string, IntPtr> slots)
    {
        if (_bindsLifecycle)
        {
            slots[nameof(CryptokiTable.C_Initialize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&Initialize;
            slots[nameof(CryptokiTable.C_Finalize)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong>)&FinalizeLibrary;
        }
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
        if (Overrides(nameof(C_SignUpdate)))
            slots[nameof(CryptokiTable.C_SignUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&SignUpdate;
        if (Overrides(nameof(C_SignFinal)))
            slots[nameof(CryptokiTable.C_SignFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&SignFinal;
        if (Overrides(nameof(C_SignRecoverInit)))
            slots[nameof(CryptokiTable.C_SignRecoverInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&SignRecoverInit;
        if (Overrides(nameof(C_SignRecover)))
            slots[nameof(CryptokiTable.C_SignRecover)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&SignRecover;
        if (Overrides(nameof(C_VerifyInit)))
            slots[nameof(CryptokiTable.C_VerifyInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&VerifyInit;
        if (Overrides(nameof(C_Verify)))
            slots[nameof(CryptokiTable.C_Verify)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&Verify;
        if (Overrides(nameof(C_VerifyUpdate)))
            slots[nameof(CryptokiTable.C_VerifyUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifyUpdate;
        if (Overrides(nameof(C_VerifyFinal)))
            slots[nameof(CryptokiTable.C_VerifyFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifyFinal;
        if (Overrides(nameof(C_VerifyRecoverInit)))
            slots[nameof(CryptokiTable.C_VerifyRecoverInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&VerifyRecoverInit;
        if (Overrides(nameof(C_VerifyRecover)))
            slots[nameof(CryptokiTable.C_VerifyRecover)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&VerifyRecover;
        if (Overrides(nameof(C_VerifySignatureInit)))
            slots[nameof(CryptokiTable.C_VerifySignatureInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifySignatureInit;
        if (Overrides(nameof(C_VerifySignature)))
            slots[nameof(CryptokiTable.C_VerifySignature)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifySignature;
        if (Overrides(nameof(C_VerifySignatureUpdate)))
            slots[nameof(CryptokiTable.C_VerifySignatureUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifySignatureUpdate;
        if (Overrides(nameof(C_VerifySignatureFinal)))
            slots[nameof(CryptokiTable.C_VerifySignatureFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&VerifySignatureFinal;
        if (Overrides(nameof(C_EncryptUpdate)))
            slots[nameof(CryptokiTable.C_EncryptUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&EncryptUpdate;
        if (Overrides(nameof(C_EncryptFinal)))
            slots[nameof(CryptokiTable.C_EncryptFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&EncryptFinal;
        if (Overrides(nameof(C_DecryptInit)))
            slots[nameof(CryptokiTable.C_DecryptInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&DecryptInit;
        if (Overrides(nameof(C_Decrypt)))
            slots[nameof(CryptokiTable.C_Decrypt)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&Decrypt;
        if (Overrides(nameof(C_DecryptUpdate)))
            slots[nameof(CryptokiTable.C_DecryptUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&DecryptUpdate;
        if (Overrides(nameof(C_DecryptFinal)))
            slots[nameof(CryptokiTable.C_DecryptFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&DecryptFinal;
        if (Overrides(nameof(C_DigestUpdate)))
            slots[nameof(CryptokiTable.C_DigestUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&DigestUpdate;
        if (Overrides(nameof(C_DigestKey)))
            slots[nameof(CryptokiTable.C_DigestKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)&DigestKey;
        if (Overrides(nameof(C_DigestFinal)))
            slots[nameof(CryptokiTable.C_DigestFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&DigestFinal;
        if (Overrides(nameof(C_DigestEncryptUpdate)))
            slots[nameof(CryptokiTable.C_DigestEncryptUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&DigestEncryptUpdate;
        if (Overrides(nameof(C_DecryptDigestUpdate)))
            slots[nameof(CryptokiTable.C_DecryptDigestUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&DecryptDigestUpdate;
        if (Overrides(nameof(C_SignEncryptUpdate)))
            slots[nameof(CryptokiTable.C_SignEncryptUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&SignEncryptUpdate;
        if (Overrides(nameof(C_DecryptVerifyUpdate)))
            slots[nameof(CryptokiTable.C_DecryptVerifyUpdate)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&DecryptVerifyUpdate;
        if (Overrides(nameof(C_GenerateKey)))
            slots[nameof(CryptokiTable.C_GenerateKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, void*, NativeCULong, NativeCULong*, NativeCULong>)&GenerateKey;
        if (Overrides(nameof(C_GenerateKeyPair)))
            slots[nameof(CryptokiTable.C_GenerateKeyPair)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, void*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong>)&GenerateKeyPair;
        if (Overrides(nameof(C_WrapKey)))
            slots[nameof(CryptokiTable.C_WrapKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong>)&WrapKey;
        if (Overrides(nameof(C_UnwrapKey)))
            slots[nameof(CryptokiTable.C_UnwrapKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong>)&UnwrapKey;
        if (Overrides(nameof(C_DeriveKey)))
            slots[nameof(CryptokiTable.C_DeriveKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong>)&DeriveKey;
        if (Overrides(nameof(C_EncapsulateKey)))
            slots[nameof(CryptokiTable.C_EncapsulateKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong>)&EncapsulateKey;
        if (Overrides(nameof(C_DecapsulateKey)))
            slots[nameof(CryptokiTable.C_DecapsulateKey)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)&DecapsulateKey;
        if (Overrides(nameof(C_WrapKeyAuthenticated)))
            slots[nameof(CryptokiTable.C_WrapKeyAuthenticated)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&WrapKeyAuthenticated;
        if (Overrides(nameof(C_UnwrapKeyAuthenticated)))
            slots[nameof(CryptokiTable.C_UnwrapKeyAuthenticated)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong>)&UnwrapKeyAuthenticated;
        if (Overrides(nameof(C_SeedRandom)))
            slots[nameof(CryptokiTable.C_SeedRandom)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&SeedRandom;
        if (Overrides(nameof(C_GetFunctionStatus)))
            slots[nameof(CryptokiTable.C_GetFunctionStatus)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&GetFunctionStatus;
        if (Overrides(nameof(C_CancelFunction)))
            slots[nameof(CryptokiTable.C_CancelFunction)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&CancelFunction;
        if (Overrides(nameof(C_CreateObject)))
            slots[nameof(CryptokiTable.C_CreateObject)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong>)&CreateObject;
        if (Overrides(nameof(C_CopyObject)))
            slots[nameof(CryptokiTable.C_CopyObject)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong>)&CopyObject;
        if (Overrides(nameof(C_DestroyObject)))
            slots[nameof(CryptokiTable.C_DestroyObject)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)&DestroyObject;
        if (Overrides(nameof(C_GetObjectSize)))
            slots[nameof(CryptokiTable.C_GetObjectSize)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)&GetObjectSize;
        if (Overrides(nameof(C_SetAttributeValue)))
            slots[nameof(CryptokiTable.C_SetAttributeValue)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong>)&SetAttributeValue;
        if (Overrides(nameof(C_InitPIN)))
            slots[nameof(CryptokiTable.C_InitPIN)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong>)&InitPIN;
        if (Overrides(nameof(C_SetPIN)))
            slots[nameof(CryptokiTable.C_SetPIN)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&SetPIN;
        if (Overrides(nameof(C_CloseAllSessions)))
            slots[nameof(CryptokiTable.C_CloseAllSessions)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&CloseAllSessions;
        if (Overrides(nameof(C_GetSessionInfo)))
            slots[nameof(CryptokiTable.C_GetSessionInfo)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong>)&GetSessionInfo;
        if (Overrides(nameof(C_GetOperationState)))
            slots[nameof(CryptokiTable.C_GetOperationState)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&GetOperationState;
        if (Overrides(nameof(C_SetOperationState)))
            slots[nameof(CryptokiTable.C_SetOperationState)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong, NativeCULong, NativeCULong>)&SetOperationState;
        if (Overrides(nameof(C_LoginUser)))
            slots[nameof(CryptokiTable.C_LoginUser)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&LoginUser;
        if (Overrides(nameof(C_SessionCancel)))
            slots[nameof(CryptokiTable.C_SessionCancel)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong>)&SessionCancel;
        if (Overrides(nameof(C_GetSessionValidationFlags)))
            slots[nameof(CryptokiTable.C_GetSessionValidationFlags)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong>)&GetSessionValidationFlags;
        if (Overrides(nameof(C_GetSlotInfo)))
            slots[nameof(CryptokiTable.C_GetSlotInfo)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong>)&GetSlotInfo;
        if (Overrides(nameof(C_GetMechanismList)))
            slots[nameof(CryptokiTable.C_GetMechanismList)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong*, NativeCULong>)&GetMechanismList;
        if (Overrides(nameof(C_GetMechanismInfo)))
            slots[nameof(CryptokiTable.C_GetMechanismInfo)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong>)&GetMechanismInfo;
        if (Overrides(nameof(C_GetInterfaceList)))
            slots[nameof(CryptokiTable.C_GetInterfaceList)] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, NativeCULong*, NativeCULong>)&GetInterfaceList;
        if (Overrides(nameof(C_MessageEncryptInit)))
            slots[nameof(CryptokiTable.C_MessageEncryptInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&MessageEncryptInit;
        if (Overrides(nameof(C_EncryptMessage)))
            slots[nameof(CryptokiTable.C_EncryptMessage)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&EncryptMessage;
        if (Overrides(nameof(C_EncryptMessageBegin)))
            slots[nameof(CryptokiTable.C_EncryptMessageBegin)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)&EncryptMessageBegin;
        if (Overrides(nameof(C_EncryptMessageNext)))
            slots[nameof(CryptokiTable.C_EncryptMessageNext)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)&EncryptMessageNext;
        if (Overrides(nameof(C_MessageEncryptFinal)))
            slots[nameof(CryptokiTable.C_MessageEncryptFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&MessageEncryptFinal;
        if (Overrides(nameof(C_MessageDecryptInit)))
            slots[nameof(CryptokiTable.C_MessageDecryptInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&MessageDecryptInit;
        if (Overrides(nameof(C_DecryptMessage)))
            slots[nameof(CryptokiTable.C_DecryptMessage)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&DecryptMessage;
        if (Overrides(nameof(C_DecryptMessageBegin)))
            slots[nameof(CryptokiTable.C_DecryptMessageBegin)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong>)&DecryptMessageBegin;
        if (Overrides(nameof(C_DecryptMessageNext)))
            slots[nameof(CryptokiTable.C_DecryptMessageNext)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong>)&DecryptMessageNext;
        if (Overrides(nameof(C_MessageDecryptFinal)))
            slots[nameof(CryptokiTable.C_MessageDecryptFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&MessageDecryptFinal;
        if (Overrides(nameof(C_MessageSignInit)))
            slots[nameof(CryptokiTable.C_MessageSignInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&MessageSignInit;
        if (Overrides(nameof(C_SignMessage)))
            slots[nameof(CryptokiTable.C_SignMessage)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&SignMessage;
        if (Overrides(nameof(C_SignMessageBegin)))
            slots[nameof(CryptokiTable.C_SignMessageBegin)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)&SignMessageBegin;
        if (Overrides(nameof(C_SignMessageNext)))
            slots[nameof(CryptokiTable.C_SignMessageNext)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong>)&SignMessageNext;
        if (Overrides(nameof(C_MessageSignFinal)))
            slots[nameof(CryptokiTable.C_MessageSignFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&MessageSignFinal;
        if (Overrides(nameof(C_MessageVerifyInit)))
            slots[nameof(CryptokiTable.C_MessageVerifyInit)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong>)&MessageVerifyInit;
        if (Overrides(nameof(C_VerifyMessage)))
            slots[nameof(CryptokiTable.C_VerifyMessage)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifyMessage;
        if (Overrides(nameof(C_VerifyMessageBegin)))
            slots[nameof(CryptokiTable.C_VerifyMessageBegin)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong>)&VerifyMessageBegin;
        if (Overrides(nameof(C_VerifyMessageNext)))
            slots[nameof(CryptokiTable.C_VerifyMessageNext)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&VerifyMessageNext;
        if (Overrides(nameof(C_MessageVerifyFinal)))
            slots[nameof(CryptokiTable.C_MessageVerifyFinal)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong>)&MessageVerifyFinal;
        if (Overrides(nameof(C_AsyncComplete)))
            slots[nameof(CryptokiTable.C_AsyncComplete)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, void*, NativeCULong>)&AsyncComplete;
        if (Overrides(nameof(C_AsyncGetID)))
            slots[nameof(CryptokiTable.C_AsyncGetID)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong>)&AsyncGetID;
        if (Overrides(nameof(C_AsyncJoin)))
            slots[nameof(CryptokiTable.C_AsyncJoin)] = (IntPtr)(delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong>)&AsyncJoin;
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
    private static NativeCULong SignUpdate(NativeCULong hSession, byte* pPart, NativeCULong ulPartLen)
    {
        if (Owner(hSession, nameof(C_SignUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_SignUpdate(hSession, In(pPart, ulPartLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignFinal(NativeCULong hSession, byte* pSignature, NativeCULong* pulSignatureLen)
    {
        if (Owner(hSession, nameof(C_SignFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulSignatureLen;
            CKR rv = m.C_SignFinal(hSession, new NativeBuffer<byte>(pSignature, length), ref length);
            *pulSignatureLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignRecoverInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_SignRecoverInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_SignRecoverInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignRecover(NativeCULong hSession, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong* pulSignatureLen)
    {
        if (Owner(hSession, nameof(C_SignRecover)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulSignatureLen;
            CKR rv = m.C_SignRecover(hSession, In(pData, ulDataLen), new NativeBuffer<byte>(pSignature, length), ref length);
            *pulSignatureLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_VerifyInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifyInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Verify(NativeCULong hSession, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong ulSignatureLen)
    {
        if (Owner(hSession, nameof(C_Verify)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_Verify(hSession, In(pData, ulDataLen), In(pSignature, ulSignatureLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyUpdate(NativeCULong hSession, byte* pPart, NativeCULong ulPartLen)
    {
        if (Owner(hSession, nameof(C_VerifyUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifyUpdate(hSession, In(pPart, ulPartLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyFinal(NativeCULong hSession, byte* pSignature, NativeCULong ulSignatureLen)
    {
        if (Owner(hSession, nameof(C_VerifyFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifyFinal(hSession, In(pSignature, ulSignatureLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyRecoverInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_VerifyRecoverInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifyRecoverInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyRecover(NativeCULong hSession, byte* pSignature, NativeCULong ulSignatureLen, byte* pData, NativeCULong* pulDataLen)
    {
        if (Owner(hSession, nameof(C_VerifyRecover)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulDataLen;
            CKR rv = m.C_VerifyRecover(hSession, In(pSignature, ulSignatureLen), new NativeBuffer<byte>(pData, length), ref length);
            *pulDataLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifySignatureInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey, byte* pSignature, NativeCULong ulSignatureLen)
    {
        if (Owner(hSession, nameof(C_VerifySignatureInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifySignatureInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey, In(pSignature, ulSignatureLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifySignature(NativeCULong hSession, byte* pData, NativeCULong ulDataLen)
    {
        if (Owner(hSession, nameof(C_VerifySignature)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifySignature(hSession, In(pData, ulDataLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifySignatureUpdate(NativeCULong hSession, byte* pPart, NativeCULong ulPartLen)
    {
        if (Owner(hSession, nameof(C_VerifySignatureUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifySignatureUpdate(hSession, In(pPart, ulPartLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifySignatureFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_VerifySignatureFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_VerifySignatureFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_EncryptUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_EncryptUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptFinal(NativeCULong hSession, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_EncryptFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_EncryptFinal(hSession, new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_DecryptInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_DecryptInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong Decrypt(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_Decrypt)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_Decrypt(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DecryptUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptFinal(NativeCULong hSession, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DecryptFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptFinal(hSession, new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DigestUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen)
    {
        if (Owner(hSession, nameof(C_DigestUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_DigestUpdate(hSession, In(pIn, ulInLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DigestKey(NativeCULong hSession, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_DigestKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_DigestKey(hSession, hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DigestFinal(NativeCULong hSession, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DigestFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DigestFinal(hSession, new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DigestEncryptUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DigestEncryptUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DigestEncryptUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptDigestUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DecryptDigestUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptDigestUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignEncryptUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_SignEncryptUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_SignEncryptUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptVerifyUpdate(NativeCULong hSession, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DecryptVerifyUpdate)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptVerifyUpdate(hSession, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GenerateKey(NativeCULong hSession, void* pMechanism, void* pTemplate, NativeCULong ulCount, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_GenerateKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong key = *phKey;
            CKR rv = m.C_GenerateKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), ReadTemplate(pTemplate, ulCount), ref key);
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GenerateKeyPair(NativeCULong hSession, void* pMechanism, void* pPublicKeyTemplate, NativeCULong ulPublicKeyAttributeCount, void* pPrivateKeyTemplate, NativeCULong ulPrivateKeyAttributeCount, NativeCULong* phPublicKey, NativeCULong* phPrivateKey)
    {
        if (Owner(hSession, nameof(C_GenerateKeyPair)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong publicKey = *phPublicKey, privateKey = *phPrivateKey;
            CKR rv = m.C_GenerateKeyPair(hSession, ReadStruct<CK_MECHANISM>(pMechanism),
                ReadTemplate(pPublicKeyTemplate, ulPublicKeyAttributeCount), ReadTemplate(pPrivateKeyTemplate, ulPrivateKeyAttributeCount),
                ref publicKey, ref privateKey);
            *phPublicKey = publicKey;
            *phPrivateKey = privateKey;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong WrapKey(NativeCULong hSession, void* pMechanism, NativeCULong hWrappingKey, NativeCULong hKey, byte* pWrappedKey, NativeCULong* pulWrappedKeyLen)
    {
        if (Owner(hSession, nameof(C_WrapKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulWrappedKeyLen;
            CKR rv = m.C_WrapKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hWrappingKey, hKey, new NativeBuffer<byte>(pWrappedKey, length), ref length);
            *pulWrappedKeyLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong UnwrapKey(NativeCULong hSession, void* pMechanism, NativeCULong hUnwrappingKey, byte* pWrappedKey, NativeCULong ulWrappedKeyLen, void* pTemplate, NativeCULong ulAttributeCount, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_UnwrapKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong key = *phKey;
            CKR rv = m.C_UnwrapKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hUnwrappingKey, In(pWrappedKey, ulWrappedKeyLen), ReadTemplate(pTemplate, ulAttributeCount), ref key);
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DeriveKey(NativeCULong hSession, void* pMechanism, NativeCULong hBaseKey, void* pTemplate, NativeCULong ulAttributeCount, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_DeriveKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong key = *phKey;
            CKR rv = m.C_DeriveKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hBaseKey, ReadTemplate(pTemplate, ulAttributeCount), ref key);
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncapsulateKey(NativeCULong hSession, void* pMechanism, NativeCULong hPublicKey, void* pTemplate, NativeCULong ulAttributeCount, byte* pCiphertext, NativeCULong* pulCiphertextLen, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_EncapsulateKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulCiphertextLen, key = *phKey;
            CKR rv = m.C_EncapsulateKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hPublicKey, ReadTemplate(pTemplate, ulAttributeCount),
                new NativeBuffer<byte>(pCiphertext, length), ref length, ref key);
            *pulCiphertextLen = length;
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecapsulateKey(NativeCULong hSession, void* pMechanism, NativeCULong hPrivateKey, void* pTemplate, NativeCULong ulAttributeCount, byte* pCiphertext, NativeCULong ulCiphertextLen, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_DecapsulateKey)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong key = *phKey;
            CKR rv = m.C_DecapsulateKey(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hPrivateKey, ReadTemplate(pTemplate, ulAttributeCount), In(pCiphertext, ulCiphertextLen), ref key);
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong WrapKeyAuthenticated(NativeCULong hSession, void* pMechanism, NativeCULong hWrappingKey, NativeCULong hKey, byte* pAssociatedData, NativeCULong ulAssociatedDataLen, byte* pWrappedKey, NativeCULong* pulWrappedKeyLen)
    {
        if (Owner(hSession, nameof(C_WrapKeyAuthenticated)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulWrappedKeyLen;
            CKR rv = m.C_WrapKeyAuthenticated(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hWrappingKey, hKey, In(pAssociatedData, ulAssociatedDataLen),
                new NativeBuffer<byte>(pWrappedKey, length), ref length);
            *pulWrappedKeyLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong UnwrapKeyAuthenticated(NativeCULong hSession, void* pMechanism, NativeCULong hUnwrappingKey, byte* pWrappedKey, NativeCULong ulWrappedKeyLen, void* pTemplate, NativeCULong ulAttributeCount, byte* pAssociatedData, NativeCULong ulAssociatedDataLen, NativeCULong* phKey)
    {
        if (Owner(hSession, nameof(C_UnwrapKeyAuthenticated)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong key = *phKey;
            CKR rv = m.C_UnwrapKeyAuthenticated(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hUnwrappingKey, In(pWrappedKey, ulWrappedKeyLen),
                ReadTemplate(pTemplate, ulAttributeCount), In(pAssociatedData, ulAssociatedDataLen), ref key);
            *phKey = key;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SeedRandom(NativeCULong hSession, byte* pIn, NativeCULong ulInLen)
    {
        if (Owner(hSession, nameof(C_SeedRandom)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_SeedRandom(hSession, In(pIn, ulInLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetFunctionStatus(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_GetFunctionStatus)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_GetFunctionStatus(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong CancelFunction(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_CancelFunction)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_CancelFunction(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong CreateObject(NativeCULong hSession, void* pTemplate, NativeCULong ulCount, NativeCULong* phObject)
    {
        if (Owner(hSession, nameof(C_CreateObject)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong objectId = *phObject;
            CKR rv = m.C_CreateObject(hSession, ReadTemplate(pTemplate, ulCount), ref objectId);
            *phObject = objectId;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong CopyObject(NativeCULong hSession, NativeCULong hObject, void* pTemplate, NativeCULong ulCount, NativeCULong* phNewObject)
    {
        if (Owner(hSession, nameof(C_CopyObject)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong newObjectId = *phNewObject;
            CKR rv = m.C_CopyObject(hSession, hObject, ReadTemplate(pTemplate, ulCount), ref newObjectId);
            *phNewObject = newObjectId;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DestroyObject(NativeCULong hSession, NativeCULong hObject)
    {
        if (Owner(hSession, nameof(C_DestroyObject)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_DestroyObject(hSession, hObject));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetObjectSize(NativeCULong hSession, NativeCULong hObject, NativeCULong* pulSize)
    {
        if (Owner(hSession, nameof(C_GetObjectSize)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong size = *pulSize;
            CKR rv = m.C_GetObjectSize(hSession, hObject, ref size);
            *pulSize = size;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SetAttributeValue(NativeCULong hSession, NativeCULong hObject, void* pTemplate, NativeCULong ulCount)
    {
        if (Owner(hSession, nameof(C_SetAttributeValue)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_SetAttributeValue(hSession, hObject, ReadTemplate(pTemplate, ulCount)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong InitPIN(NativeCULong hSession, byte* pIn, NativeCULong ulInLen)
    {
        if (Owner(hSession, nameof(C_InitPIN)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_InitPIN(hSession, In(pIn, ulInLen))); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SetPIN(NativeCULong hSession, byte* pOldPin, NativeCULong ulOldLen, byte* pNewPin, NativeCULong ulNewLen)
    {
        if (Owner(hSession, nameof(C_SetPIN)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_SetPIN(hSession, In(pOldPin, ulOldLen), In(pNewPin, ulNewLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong CloseAllSessions(NativeCULong slotId)
    {
        if (Owner(slotId, nameof(C_CloseAllSessions)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_CloseAllSessions(slotId));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetSessionInfo(NativeCULong hSession, void* pInfo)
    {
        if (Owner(hSession, nameof(C_GetSessionInfo)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            CK_SESSION_INFO info = ReadStruct<CK_SESSION_INFO>(pInfo);
            CKR rv = m.C_GetSessionInfo(hSession, ref info);
            WriteStruct(pInfo, in info);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetOperationState(NativeCULong hSession, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_GetOperationState)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_GetOperationState(hSession, new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SetOperationState(NativeCULong hSession, byte* pState, NativeCULong ulStateLen, NativeCULong hEncryptionKey, NativeCULong hAuthenticationKey)
    {
        if (Owner(hSession, nameof(C_SetOperationState)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_SetOperationState(hSession, In(pState, ulStateLen), hEncryptionKey, hAuthenticationKey));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong LoginUser(NativeCULong hSession, NativeCULong userType, byte* pPin, NativeCULong ulPinLen, byte* pUsername, NativeCULong ulUsernameLen)
    {
        if (Owner(hSession, nameof(C_LoginUser)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_LoginUser(hSession, userType, In(pPin, ulPinLen), In(pUsername, ulUsernameLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SessionCancel(NativeCULong hSession, NativeCULong flags)
    {
        if (Owner(hSession, nameof(C_SessionCancel)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_SessionCancel(hSession, flags));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetSessionValidationFlags(NativeCULong hSession, NativeCULong type, NativeCULong* pFlags)
    {
        if (Owner(hSession, nameof(C_GetSessionValidationFlags)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong flags = *pFlags;
            CKR rv = m.C_GetSessionValidationFlags(hSession, type, ref flags);
            *pFlags = flags;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetSlotInfo(NativeCULong slotId, void* pInfo)
    {
        if (Owner(slotId, nameof(C_GetSlotInfo)) is not { } m) return Rv(CKR.CKR_SLOT_ID_INVALID);
        try
        {
            CK_SLOT_INFO info = ReadStruct<CK_SLOT_INFO>(pInfo);
            CKR rv = m.C_GetSlotInfo(slotId, ref info);
            WriteStruct(pInfo, in info);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetMechanismList(NativeCULong slotId, NativeCULong* pMechanismList, NativeCULong* pulCount)
    {
        if (Owner(slotId, nameof(C_GetMechanismList)) is not { } m) return Rv(CKR.CKR_SLOT_ID_INVALID);
        try
        {
            NativeCULong count = *pulCount;
            CKR rv = m.C_GetMechanismList(slotId, new NativeBuffer<NativeCULong>(pMechanismList, count), ref count);
            *pulCount = count;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetMechanismInfo(NativeCULong slotId, NativeCULong type, void* pInfo)
    {
        if (Owner(slotId, nameof(C_GetMechanismInfo)) is not { } m) return Rv(CKR.CKR_SLOT_ID_INVALID);
        try
        {
            CK_MECHANISM_INFO info = ReadStruct<CK_MECHANISM_INFO>(pInfo);
            CKR rv = m.C_GetMechanismInfo(slotId, type, ref info);
            WriteStruct(pInfo, in info);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong GetInterfaceList(void* pInterfacesList, NativeCULong* pulCount)
    {
        if (Active(nameof(C_GetInterfaceList)) is not { } m) return Rv(CKR.CKR_GENERAL_ERROR);
        try
        {
            NativeCULong count = *pulCount;
            // CK_INTERFACE is packed on Windows: decode into managed entries, then write each back.
            var interfaces = new CK_INTERFACE[pInterfacesList is null ? 0 : checked((int)(ulong)count)];
            CKR rv = m.C_GetInterfaceList(pInterfacesList is null, interfaces, ref count);
            int stride = UnmanagedMemory.SizeOf<CK_INTERFACE>();
            for (int i = 0; i < interfaces.Length; i++)
                UnmanagedMemory.Write((IntPtr)((byte*)pInterfacesList + i * stride), in interfaces[i]);
            *pulCount = count;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageEncryptInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_MessageEncryptInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageEncryptInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptMessage(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pAssociatedData, NativeCULong ulAssociatedDataLen, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_EncryptMessage)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_EncryptMessage(hSession, pParameter, ulParameterLen, In(pAssociatedData, ulAssociatedDataLen), In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptMessageBegin(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pAssociatedData, NativeCULong ulAssociatedDataLen)
    {
        if (Owner(hSession, nameof(C_EncryptMessageBegin)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_EncryptMessageBegin(hSession, pParameter, ulParameterLen, In(pAssociatedData, ulAssociatedDataLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong EncryptMessageNext(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen, NativeCULong flags)
    {
        if (Owner(hSession, nameof(C_EncryptMessageNext)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_EncryptMessageNext(hSession, pParameter, ulParameterLen, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length, flags);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageEncryptFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_MessageEncryptFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageEncryptFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageDecryptInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_MessageDecryptInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageDecryptInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptMessage(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pAssociatedData, NativeCULong ulAssociatedDataLen, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen)
    {
        if (Owner(hSession, nameof(C_DecryptMessage)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptMessage(hSession, pParameter, ulParameterLen, In(pAssociatedData, ulAssociatedDataLen), In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptMessageBegin(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pAssociatedData, NativeCULong ulAssociatedDataLen)
    {
        if (Owner(hSession, nameof(C_DecryptMessageBegin)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_DecryptMessageBegin(hSession, pParameter, ulParameterLen, In(pAssociatedData, ulAssociatedDataLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong DecryptMessageNext(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pIn, NativeCULong ulInLen, byte* pOut, NativeCULong* pulOutLen, NativeCULong flags)
    {
        if (Owner(hSession, nameof(C_DecryptMessageNext)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulOutLen;
            CKR rv = m.C_DecryptMessageNext(hSession, pParameter, ulParameterLen, In(pIn, ulInLen), new NativeBuffer<byte>(pOut, length), ref length, flags);
            *pulOutLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageDecryptFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_MessageDecryptFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageDecryptFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageSignInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_MessageSignInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageSignInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignMessage(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong* pulSignatureLen)
    {
        if (Owner(hSession, nameof(C_SignMessage)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulSignatureLen;
            CKR rv = m.C_SignMessage(hSession, pParameter, ulParameterLen, In(pData, ulDataLen), new NativeBuffer<byte>(pSignature, length), ref length);
            *pulSignatureLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignMessageBegin(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen)
    {
        if (Owner(hSession, nameof(C_SignMessageBegin)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_SignMessageBegin(hSession, pParameter, ulParameterLen));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong SignMessageNext(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong* pulSignatureLen)
    {
        if (Owner(hSession, nameof(C_SignMessageNext)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong length = *pulSignatureLen;
            CKR rv = m.C_SignMessageNext(hSession, pParameter, ulParameterLen, In(pData, ulDataLen), new NativeBuffer<byte>(pSignature, length), ref length);
            *pulSignatureLen = length;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageSignFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_MessageSignFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageSignFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageVerifyInit(NativeCULong hSession, void* pMechanism, NativeCULong hKey)
    {
        if (Owner(hSession, nameof(C_MessageVerifyInit)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageVerifyInit(hSession, ReadStruct<CK_MECHANISM>(pMechanism), hKey)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyMessage(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong ulSignatureLen)
    {
        if (Owner(hSession, nameof(C_VerifyMessage)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_VerifyMessage(hSession, pParameter, ulParameterLen, In(pData, ulDataLen), In(pSignature, ulSignatureLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyMessageBegin(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen)
    {
        if (Owner(hSession, nameof(C_VerifyMessageBegin)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_VerifyMessageBegin(hSession, pParameter, ulParameterLen));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong VerifyMessageNext(NativeCULong hSession, IntPtr pParameter, NativeCULong ulParameterLen, byte* pData, NativeCULong ulDataLen, byte* pSignature, NativeCULong ulSignatureLen)
    {
        if (Owner(hSession, nameof(C_VerifyMessageNext)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_VerifyMessageNext(hSession, pParameter, ulParameterLen, In(pData, ulDataLen), In(pSignature, ulSignatureLen)));
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong MessageVerifyFinal(NativeCULong hSession)
    {
        if (Owner(hSession, nameof(C_MessageVerifyFinal)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try { return Rv(m.C_MessageVerifyFinal(hSession)); }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong AsyncComplete(NativeCULong hSession, byte* pFunctionName, void* pResult)
    {
        if (Owner(hSession, nameof(C_AsyncComplete)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            CK_ASYNC_DATA result = ReadStruct<CK_ASYNC_DATA>(pResult);
            CKR rv = m.C_AsyncComplete(hSession, Marshal.PtrToStringUTF8((IntPtr)pFunctionName) ?? "", ref result);
            WriteStruct(pResult, in result);
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong AsyncGetID(NativeCULong hSession, byte* pFunctionName, NativeCULong* pulID)
    {
        if (Owner(hSession, nameof(C_AsyncGetID)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            NativeCULong id = *pulID;
            CKR rv = m.C_AsyncGetID(hSession, Marshal.PtrToStringUTF8((IntPtr)pFunctionName) ?? "", ref id);
            *pulID = id;
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong AsyncJoin(NativeCULong hSession, byte* pFunctionName, NativeCULong ulID, byte* pData, NativeCULong ulData)
    {
        if (Owner(hSession, nameof(C_AsyncJoin)) is not { } m) return Rv(CKR.CKR_SESSION_HANDLE_INVALID);
        try
        {
            return Rv(m.C_AsyncJoin(hSession, Marshal.PtrToStringUTF8((IntPtr)pFunctionName) ?? "", ulID, In(pData, ulData)));
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
