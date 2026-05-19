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
}
