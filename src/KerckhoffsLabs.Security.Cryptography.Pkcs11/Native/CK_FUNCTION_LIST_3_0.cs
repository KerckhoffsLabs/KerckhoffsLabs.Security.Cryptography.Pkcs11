namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// PKCS#11 v3.0 function-list struct returned via C_GetInterface for the "PKCS 11" interface.
/// Layout extends CK_FUNCTION_LIST: same CK_VERSION header followed by the v2.40 function
/// pointers, then the v3.0 additions in declaration order
/// (C_GetInterfaceList, C_GetInterface, C_LoginUser, C_SessionCancel,
/// followed by the 16 message-based AEAD functions).
/// </summary>
[PlatformSpecificPack]
internal struct CK_FUNCTION_LIST_3_0
{
    /// <summary>Cryptoki version, expected to be {3, 0} or higher.</summary>
    internal CK_VERSION version;

    // v2.40 function pointers — same order as CK_FUNCTION_LIST.
    internal IntPtr C_Initialize;
    internal IntPtr C_Finalize;
    internal IntPtr C_GetInfo;
    internal IntPtr C_GetFunctionList;
    internal IntPtr C_GetSlotList;
    internal IntPtr C_GetSlotInfo;
    internal IntPtr C_GetTokenInfo;
    internal IntPtr C_GetMechanismList;
    internal IntPtr C_GetMechanismInfo;
    internal IntPtr C_InitToken;
    internal IntPtr C_InitPIN;
    internal IntPtr C_SetPIN;
    internal IntPtr C_OpenSession;
    internal IntPtr C_CloseSession;
    internal IntPtr C_CloseAllSessions;
    internal IntPtr C_GetSessionInfo;
    internal IntPtr C_GetOperationState;
    internal IntPtr C_SetOperationState;
    internal IntPtr C_Login;
    internal IntPtr C_Logout;
    internal IntPtr C_CreateObject;
    internal IntPtr C_CopyObject;
    internal IntPtr C_DestroyObject;
    internal IntPtr C_GetObjectSize;
    internal IntPtr C_GetAttributeValue;
    internal IntPtr C_SetAttributeValue;
    internal IntPtr C_FindObjectsInit;
    internal IntPtr C_FindObjects;
    internal IntPtr C_FindObjectsFinal;
    internal IntPtr C_EncryptInit;
    internal IntPtr C_Encrypt;
    internal IntPtr C_EncryptUpdate;
    internal IntPtr C_EncryptFinal;
    internal IntPtr C_DecryptInit;
    internal IntPtr C_Decrypt;
    internal IntPtr C_DecryptUpdate;
    internal IntPtr C_DecryptFinal;
    internal IntPtr C_DigestInit;
    internal IntPtr C_Digest;
    internal IntPtr C_DigestUpdate;
    internal IntPtr C_DigestKey;
    internal IntPtr C_DigestFinal;
    internal IntPtr C_SignInit;
    internal IntPtr C_Sign;
    internal IntPtr C_SignUpdate;
    internal IntPtr C_SignFinal;
    internal IntPtr C_SignRecoverInit;
    internal IntPtr C_SignRecover;
    internal IntPtr C_VerifyInit;
    internal IntPtr C_Verify;
    internal IntPtr C_VerifyUpdate;
    internal IntPtr C_VerifyFinal;
    internal IntPtr C_VerifyRecoverInit;
    internal IntPtr C_VerifyRecover;
    internal IntPtr C_DigestEncryptUpdate;
    internal IntPtr C_DecryptDigestUpdate;
    internal IntPtr C_SignEncryptUpdate;
    internal IntPtr C_DecryptVerifyUpdate;
    internal IntPtr C_GenerateKey;
    internal IntPtr C_GenerateKeyPair;
    internal IntPtr C_WrapKey;
    internal IntPtr C_UnwrapKey;
    internal IntPtr C_DeriveKey;
    internal IntPtr C_SeedRandom;
    internal IntPtr C_GenerateRandom;
    internal IntPtr C_GetFunctionStatus;
    internal IntPtr C_CancelFunction;
    internal IntPtr C_WaitForSlotEvent;

    // v3.0 additions, in spec order.
    internal IntPtr C_GetInterfaceList;
    internal IntPtr C_GetInterface;
    internal IntPtr C_LoginUser;
    internal IntPtr C_SessionCancel;
    internal IntPtr C_MessageEncryptInit;
    internal IntPtr C_EncryptMessage;
    internal IntPtr C_EncryptMessageBegin;
    internal IntPtr C_EncryptMessageNext;
    internal IntPtr C_MessageEncryptFinal;
    internal IntPtr C_MessageDecryptInit;
    internal IntPtr C_DecryptMessage;
    internal IntPtr C_DecryptMessageBegin;
    internal IntPtr C_DecryptMessageNext;
    internal IntPtr C_MessageDecryptFinal;
    internal IntPtr C_MessageSignInit;
    internal IntPtr C_SignMessage;
    internal IntPtr C_SignMessageBegin;
    internal IntPtr C_SignMessageNext;
    internal IntPtr C_MessageSignFinal;
    internal IntPtr C_MessageVerifyInit;
    internal IntPtr C_VerifyMessage;
    internal IntPtr C_VerifyMessageBegin;
    internal IntPtr C_VerifyMessageNext;
    internal IntPtr C_MessageVerifyFinal;
}
