using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds the raw <c>delegate* unmanaged[Cdecl]&lt;...&gt;</c> function pointers for every
/// PKCS#11 cryptoki function the library binds. Populated by direct cast from
/// <see cref="CK_FUNCTION_LIST"/> / <see cref="CK_FUNCTION_LIST_3_0"/> / <see cref="CK_FUNCTION_LIST_3_2"/>
/// entries; no <c>Marshal.GetDelegateForFunctionPointer&lt;T&gt;</c> on this path so the
/// dispatch table is fully Native AOT compatible.
/// </summary>
/// <remarks>
/// Wrapper methods on <see cref="Delegates"/> do the per-call marshalling (pinning
/// <c>byte[]</c> / <c>CK_*[]</c> / <c>NativeCULong[]</c>, taking <c>fixed</c> addresses of
/// ref-struct parameters, converting <c>bool</c>↔<c>byte</c>) so the public dispatch
/// surface stays identical to the prior delegate-based version.
/// </remarks>
internal sealed unsafe class FunctionPointers
{
    /// <summary>Cryptoki <c>CK_RV C_Finalize(CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Finalize;

    /// <summary>Cryptoki <c>CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseSession;

    /// <summary>Cryptoki <c>CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseAllSessions;

    /// <summary>Cryptoki <c>CK_RV C_Logout(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_Logout;

    /// <summary>Cryptoki <c>CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DestroyObject;

    /// <summary>Cryptoki <c>CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<byte, NativeCULong*, NativeCULong*, NativeCULong> C_GetSlotList;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GetMechanismList;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong> C_GetMechanismInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismInfo</c> — Pack=1 Windows layout.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO_Windows*, NativeCULong> C_GetMechanismInfo_Windows;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong> C_GetSessionInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionInfo</c> — Pack=1 Windows layout.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO_Windows*, NativeCULong> C_GetSessionInfo_Windows;

    /// <summary>Cryptoki <c>CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong, NativeCULong*, NativeCULong> C_FindObjects;

    /// <summary>Cryptoki <c>CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_FindObjectsFinal;

    /// <summary>Cryptoki <c>CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)</c> (v3.0+).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_SessionCancel;

    /// <summary>Cryptoki <c>CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CancelFunction;

    // ── Setup / lifecycle / PIN / login ─────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_Initialize(CK_VOID_PTR pInitArgs)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Initialize;

    /// <summary>Cryptoki <c>CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong> C_GetFunctionList;

    /// <summary>Cryptoki <c>CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong> C_InitToken;

    /// <summary>Cryptoki <c>CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_InitPIN;

    /// <summary>Cryptoki <c>CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_SetPIN;

    /// <summary>Cryptoki <c>CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, NativeCULong> C_Login;

    /// <summary>Cryptoki <c>CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_GetOperationState;

    /// <summary>Cryptoki <c>CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong, NativeCULong, NativeCULong> C_SetOperationState;

    /// <summary>Cryptoki <c>CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_SeedRandom;

    /// <summary>Cryptoki <c>CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_GenerateRandom;

    // ── Streaming crypto ─────────────────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Encrypt;

    /// <summary>Cryptoki <c>CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Decrypt;

    /// <summary>Cryptoki <c>CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Digest;

    /// <summary>Cryptoki <c>CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_DigestUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DigestKey;

    /// <summary>Cryptoki <c>CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_DigestFinal;

    /// <summary>Cryptoki <c>CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Sign;

    /// <summary>Cryptoki <c>CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_SignUpdate;

    /// <summary>Cryptoki <c>CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignFinal;

    /// <summary>Cryptoki <c>CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignRecover;

    /// <summary>Cryptoki <c>CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_Verify;

    /// <summary>Cryptoki <c>CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyUpdate;

    /// <summary>Cryptoki <c>CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyFinal;

    /// <summary>Cryptoki <c>CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_VerifyRecover;

    /// <summary>Cryptoki <c>CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DigestEncryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptDigestUpdate;

    /// <summary>Cryptoki <c>CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignEncryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptVerifyUpdate;

    // ── Object / attribute functions ─────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_CreateObject;

    /// <summary>Cryptoki <c>CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_CopyObject;

    /// <summary>Cryptoki <c>CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_GetAttributeValue;

    /// <summary>Cryptoki <c>CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_SetAttributeValue;

    /// <summary>Cryptoki <c>CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong> C_FindObjectsInit;

    // ── Crypto-init functions (ref CK_MECHANISM) ─────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_EncryptInit;

    /// <summary>Cryptoki <c>CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_DecryptInit;

    /// <summary>Cryptoki <c>CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong> C_DigestInit;

    /// <summary>Cryptoki <c>CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_SignInit;

    /// <summary>Cryptoki <c>CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_SignRecoverInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_VerifyInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_VerifyRecoverInit;

    // ── Key-management functions ──────────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_GenerateKey;

    /// <summary>Cryptoki <c>CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, CK_ATTRIBUTE*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GenerateKeyPair;

    /// <summary>Cryptoki <c>CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKey;

    /// <summary>Cryptoki <c>CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKey;

    /// <summary>Cryptoki <c>CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, NativeCULong*, NativeCULong> C_DeriveKey;

    // ── Session / lifecycle stragglers ───────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, IntPtr, IntPtr, NativeCULong*, NativeCULong> C_OpenSession;

    /// <summary>Cryptoki <c>CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong> C_GetObjectSize;

    /// <summary>Cryptoki <c>CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_GetFunctionStatus;

    /// <summary>Cryptoki <c>CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, IntPtr, NativeCULong> C_WaitForSlotEvent;

    // ── v3.0 entry / login ───────────────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS ulFlags)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong> C_GetInterface;

    /// <summary>Cryptoki <c>CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_LoginUser;

    // ── Message-AEAD family (v3.0) ───────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_MessageEncryptInit;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptMessage;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong> C_EncryptMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong> C_EncryptMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageEncryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_MessageDecryptInit;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptMessage;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong> C_DecryptMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong> C_DecryptMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageDecryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_MessageSignInit;

    /// <summary>Cryptoki <c>CK_RV C_SignMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignMessage;

    /// <summary>Cryptoki <c>CK_RV C_SignMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong> C_SignMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_SignMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageSignFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong> C_MessageVerifyInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyMessage;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong> C_VerifyMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageVerifyFinal;

    // ── v3.2 PQC / signature / async / authenticated-wrap ────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_EncapsulateKey(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong> C_EncapsulateKey;

    /// <summary>Cryptoki <c>CK_RV C_DecapsulateKey(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_DecapsulateKey;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureInit(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignatureInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignature;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignatureUpdate;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_VerifySignatureFinal;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession, CK_FLAGS ulFlags, CK_FLAGS_PTR pulFlags)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong> C_GetSessionValidationFlags;

    /// <summary>Cryptoki <c>CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA*, NativeCULong> C_AsyncComplete;

    /// <summary>Cryptoki <c>CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_AsyncGetID;

    /// <summary>Cryptoki <c>CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulDataLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_AsyncJoin;

    /// <summary>Cryptoki <c>CK_RV C_WrapKeyAuthenticated(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKeyAuthenticated;

    /// <summary>Cryptoki <c>CK_RV C_UnwrapKeyAuthenticated(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKeyAuthenticated;

    // ── Windows-layout variants (Pack=1) ─────────────────────────────────────────
    // Each fptr below is the Pack=1 twin of its unified sibling above.
    // Both are cast from the SAME native function-list entry; only the managed
    // struct layout differs. Used on Windows where the PKCS#11 ABI uses packed
    // structs. Functions whose structs are non-blittable (CK_*_INFO_Windows) are
    // kept as delegates and are not listed here.

    /// <summary>Windows-layout (Pack=1) twin of <c>C_CreateObject</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_CreateObject_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_CopyObject</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_CopyObject_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_GetAttributeValue</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_GetAttributeValue_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_SetAttributeValue</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_SetAttributeValue_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_FindObjectsInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong> C_FindObjectsInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_EncryptInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_EncryptInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_DecryptInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_DecryptInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_DigestInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong> C_DigestInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_SignInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_SignInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_SignRecoverInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_SignRecoverInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_VerifyInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_VerifyInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_VerifyRecoverInit</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_VerifyRecoverInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_GenerateKey</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_GenerateKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_GenerateKeyPair</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, CK_ATTRIBUTE_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GenerateKeyPair_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_WrapKey</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_UnwrapKey</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_DeriveKey</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, NativeCULong*, NativeCULong> C_DeriveKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_MessageEncryptInit</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_MessageEncryptInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_MessageDecryptInit</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_MessageDecryptInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_MessageSignInit</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_MessageSignInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_MessageVerifyInit</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong> C_MessageVerifyInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_EncapsulateKey</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong> C_EncapsulateKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_DecapsulateKey</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_DecapsulateKey_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_VerifySignatureInit</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignatureInit_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_AsyncComplete</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, CK_ASYNC_DATA_Windows*, NativeCULong> C_AsyncComplete_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_WrapKeyAuthenticated</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKeyAuthenticated_Windows;

    /// <summary>Windows-layout (Pack=1) twin of <c>C_UnwrapKeyAuthenticated</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_MECHANISM_Windows*, NativeCULong, byte*, NativeCULong, CK_ATTRIBUTE_Windows*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKeyAuthenticated_Windows;
}
