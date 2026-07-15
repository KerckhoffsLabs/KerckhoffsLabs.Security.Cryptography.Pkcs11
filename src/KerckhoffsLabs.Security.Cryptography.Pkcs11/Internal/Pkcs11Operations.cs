namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// PKCS#11 native function names, used as the operation label when a non-<c>CKR_OK</c> return value
/// is mapped to a <see cref="Exceptions.Pkcs11Exception"/>. Centralizing them keeps the label for a
/// given <c>C_*</c> call written once and referenced by name rather than repeated as a string literal.
/// </summary>
internal static class Pkcs11Operations
{
    public const string OpCancelFunction = "C_CancelFunction";
    public const string OpCopyObject = "C_CopyObject";
    public const string OpCreateObject = "C_CreateObject";
    public const string OpDecapsulateKey = "C_DecapsulateKey";
    public const string OpDecrypt = "C_Decrypt";
    public const string OpDecryptDigestUpdate = "C_DecryptDigestUpdate";
    public const string OpDecryptFinal = "C_DecryptFinal";
    public const string OpDecryptInit = "C_DecryptInit";
    public const string OpDecryptMessage = "C_DecryptMessage";
    public const string OpDecryptUpdate = "C_DecryptUpdate";
    public const string OpDecryptVerifyUpdate = "C_DecryptVerifyUpdate";
    public const string OpDeriveKey = "C_DeriveKey";
    public const string OpDestroyObject = "C_DestroyObject";
    public const string OpDigest = "C_Digest";
    public const string OpDigestEncryptUpdate = "C_DigestEncryptUpdate";
    public const string OpDigestFinal = "C_DigestFinal";
    public const string OpDigestInit = "C_DigestInit";
    public const string OpDigestKey = "C_DigestKey";
    public const string OpDigestUpdate = "C_DigestUpdate";
    public const string OpEncapsulateKey = "C_EncapsulateKey";
    public const string OpEncrypt = "C_Encrypt";
    public const string OpEncryptFinal = "C_EncryptFinal";
    public const string OpEncryptInit = "C_EncryptInit";
    public const string OpEncryptMessage = "C_EncryptMessage";
    public const string OpEncryptUpdate = "C_EncryptUpdate";
    public const string OpFindObjects = "C_FindObjects";
    public const string OpFindObjectsFinal = "C_FindObjectsFinal";
    public const string OpFindObjectsInit = "C_FindObjectsInit";
    public const string OpGenerateKey = "C_GenerateKey";
    public const string OpGenerateKeyPair = "C_GenerateKeyPair";
    public const string OpGenerateRandom = "C_GenerateRandom";
    public const string OpGetAttributeValue = "C_GetAttributeValue";
    public const string OpGetFunctionStatus = "C_GetFunctionStatus";
    public const string OpGetObjectSize = "C_GetObjectSize";
    public const string OpGetOperationState = "C_GetOperationState";
    public const string OpGetSessionInfo = "C_GetSessionInfo";
    public const string OpGetSessionValidationFlags = "C_GetSessionValidationFlags";
    public const string OpInitPIN = "C_InitPIN";
    public const string OpLogin = "C_Login";
    public const string OpLoginUser = "C_LoginUser";
    public const string OpLogout = "C_Logout";
    public const string OpMessageDecryptInit = "C_MessageDecryptInit";
    public const string OpMessageEncryptInit = "C_MessageEncryptInit";
    public const string OpSeedRandom = "C_SeedRandom";
    public const string OpSessionCancel = "C_SessionCancel";
    public const string OpSetAttributeValue = "C_SetAttributeValue";
    public const string OpSetOperationState = "C_SetOperationState";
    public const string OpSetPIN = "C_SetPIN";
    public const string OpSign = "C_Sign";
    public const string OpSignInit = "C_SignInit";
    public const string OpUnwrapKey = "C_UnwrapKey";
    public const string OpUnwrapKeyAuthenticated = "C_UnwrapKeyAuthenticated";
    public const string OpVerify = "C_Verify";
    public const string OpVerifyFinal = "C_VerifyFinal";
    public const string OpVerifyInit = "C_VerifyInit";
    public const string OpVerifyRecover = "C_VerifyRecover";
    public const string OpVerifyRecoverInit = "C_VerifyRecoverInit";
    public const string OpVerifySignature = "C_VerifySignature";
    public const string OpVerifySignatureFinal = "C_VerifySignatureFinal";
    public const string OpVerifySignatureInit = "C_VerifySignatureInit";
    public const string OpVerifySignatureUpdate = "C_VerifySignatureUpdate";
    public const string OpVerifyUpdate = "C_VerifyUpdate";
    public const string OpWrapKey = "C_WrapKey";
    public const string OpWrapKeyAuthenticated = "C_WrapKeyAuthenticated";
}
