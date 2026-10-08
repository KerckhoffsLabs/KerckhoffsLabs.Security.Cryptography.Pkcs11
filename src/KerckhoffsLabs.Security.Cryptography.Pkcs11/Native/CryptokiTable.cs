using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// The module's function table: one <c>delegate* unmanaged[Cdecl]</c> per Cryptoki function, in the
/// slot order of <c>CK_FUNCTION_LIST_3_2</c>. The v2.40 <c>CK_FUNCTION_LIST</c> is its first
/// <see cref="V240SlotCount"/> slots and <c>CK_FUNCTION_LIST_3_0</c> its first <see cref="V30SlotCount"/>:
/// the headers generate all three from one <c>pkcs11f.h</c>, so each table extends the one before.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Read"/> copies a module's table slot by slot, and only as many slots as the table's
/// verified version defines, so a shorter table is never read past its end. The layout this assumes —
/// the slot order and the offset of the first slot after the <c>CK_VERSION</c> header — is checked
/// against the C compiler's layout of the OASIS headers on every platform by <c>AbiOracleTests</c>.
/// </para>
/// <para>
/// A parameter that points to a struct whose layout differs on Windows (Pack=1) is declared
/// <c>void*</c>, so the wrapper passes the unified or the <c>_Windows</c> struct through the same slot.
/// No marshalling is involved, so the table is Native AOT compatible.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the module's function table. Its fields are unmanaged function pointers, " +
    "which C# permits only in an unsafe context, and they are what lets the library call a PKCS#11 module " +
    "without marshalling, Native AOT included. Read is the only code that dereferences a pointer: it copies " +
    "the module's table slot by slot, never more slots than the table's verified version defines (and never " +
    "more than this struct holds), from the offset the slots start at. That layout, slot order and first-slot " +
    "offset on every platform, is checked against the C compiler's layout of the OASIS headers by " +
    "AbiOracleTests, and the binding by TableLoaderTests. Suppressed at the type, as for LowLevelPkcs11Library, so an " +
    "unsafe block outside the cryptoki boundary is still reported.")]
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CryptokiTable
{
    /// <summary>Slots in a v2.40 <c>CK_FUNCTION_LIST</c>.</summary>
    internal const int V240SlotCount = 68;

    /// <summary>Slots in a v3.0 (and v3.1) <c>CK_FUNCTION_LIST_3_0</c>.</summary>
    internal const int V30SlotCount = 92;

    /// <summary>Slots in a v3.2 <c>CK_FUNCTION_LIST_3_2</c>.</summary>
    internal const int V32SlotCount = 104;

    /// <summary>
    /// Offset of the first slot in a native function list: after the two-byte <c>CK_VERSION</c> header,
    /// which is padded to pointer alignment except under the cryptoki <c>pack(1)</c> on Windows.
    /// </summary>
    internal static int FirstSlotOffset => Pkcs11Marshal.IsWindows ? Unsafe.SizeOf<CK_VERSION>() : IntPtr.Size;

    /// <summary>Copies the first <paramref name="slotCount"/> slots of the native function list at <paramref name="functionList"/>.</summary>
    internal static CryptokiTable Read(IntPtr functionList, int slotCount)
    {
        // Two checks rather than the (uint) cast idiom: this assembly builds with checked arithmetic, so the
        // cast would throw OverflowException for a negative count instead of reaching the comparison.
        ArgumentOutOfRangeException.ThrowIfNegative(slotCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(slotCount, V32SlotCount);

        CryptokiTable table = default;
        Span<IntPtr> slots = MemoryMarshal.Cast<CryptokiTable, IntPtr>(new Span<CryptokiTable>(ref table));
        byte* first = (byte*)functionList + FirstSlotOffset;
        for (int i = 0; i < slotCount; i++)
            slots[i] = Unsafe.ReadUnaligned<IntPtr>(first + i * IntPtr.Size); // unaligned under pack(1)
        return table;
    }


    /// <summary>Cryptoki <c>CK_RV C_Initialize(CK_VOID_PTR pInitArgs)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Initialize;

    /// <summary>Cryptoki <c>CK_RV C_Finalize(CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Finalize;

    /// <summary>Cryptoki <c>CK_RV C_GetInfo(CK_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<void*, NativeCULong> C_GetInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong> C_GetFunctionList;

    /// <summary>Cryptoki <c>CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<byte, NativeCULong*, NativeCULong*, NativeCULong> C_GetSlotList;

    /// <summary>Cryptoki <c>CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong> C_GetSlotInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong> C_GetTokenInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GetMechanismList;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong> C_GetMechanismInfo;

    /// <summary>Cryptoki <c>CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong> C_InitToken;

    /// <summary>Cryptoki <c>CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_InitPIN;

    /// <summary>Cryptoki <c>CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_SetPIN;

    /// <summary>Cryptoki <c>CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, IntPtr, IntPtr, NativeCULong*, NativeCULong> C_OpenSession;

    /// <summary>Cryptoki <c>CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseSession;

    /// <summary>Cryptoki <c>CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseAllSessions;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong> C_GetSessionInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_GetOperationState;

    /// <summary>Cryptoki <c>CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong, NativeCULong, NativeCULong> C_SetOperationState;

    /// <summary>Cryptoki <c>CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, NativeCULong> C_Login;

    /// <summary>Cryptoki <c>CK_RV C_Logout(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_Logout;

    /// <summary>Cryptoki <c>CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong> C_CreateObject;

    /// <summary>Cryptoki <c>CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong> C_CopyObject;

    /// <summary>Cryptoki <c>CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DestroyObject;

    /// <summary>Cryptoki <c>CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong> C_GetObjectSize;

    /// <summary>Cryptoki <c>CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong> C_GetAttributeValue;

    /// <summary>Cryptoki <c>CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, void*, NativeCULong, NativeCULong> C_SetAttributeValue;

    /// <summary>Cryptoki <c>CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_FindObjectsInit;

    /// <summary>Cryptoki <c>CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, NativeCULong, NativeCULong*, NativeCULong> C_FindObjects;

    /// <summary>Cryptoki <c>CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_FindObjectsFinal;

    /// <summary>Cryptoki <c>CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_EncryptInit;

    /// <summary>Cryptoki <c>CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Encrypt;

    /// <summary>Cryptoki <c>CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_DecryptInit;

    /// <summary>Cryptoki <c>CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Decrypt;

    /// <summary>Cryptoki <c>CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong> C_DigestInit;

    /// <summary>Cryptoki <c>CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Digest;

    /// <summary>Cryptoki <c>CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_DigestUpdate;

    /// <summary>Cryptoki <c>CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DigestKey;

    /// <summary>Cryptoki <c>CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_DigestFinal;

    /// <summary>Cryptoki <c>CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_SignInit;

    /// <summary>Cryptoki <c>CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_Sign;

    /// <summary>Cryptoki <c>CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_SignUpdate;

    /// <summary>Cryptoki <c>CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignFinal;

    /// <summary>Cryptoki <c>CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_SignRecoverInit;

    /// <summary>Cryptoki <c>CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignRecover;

    /// <summary>Cryptoki <c>CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_VerifyInit;

    /// <summary>Cryptoki <c>CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_Verify;

    /// <summary>Cryptoki <c>CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyUpdate;

    /// <summary>Cryptoki <c>CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyFinal;

    /// <summary>Cryptoki <c>CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_VerifyRecoverInit;

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

    /// <summary>Cryptoki <c>CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, void*, NativeCULong, NativeCULong*, NativeCULong> C_GenerateKey;

    /// <summary>Cryptoki <c>CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, void*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong*, NativeCULong> C_GenerateKeyPair;

    /// <summary>Cryptoki <c>CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKey;

    /// <summary>Cryptoki <c>CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKey;

    /// <summary>Cryptoki <c>CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, NativeCULong*, NativeCULong> C_DeriveKey;

    /// <summary>Cryptoki <c>CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_SeedRandom;

    /// <summary>Cryptoki <c>CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_GenerateRandom;

    /// <summary>Cryptoki <c>CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_GetFunctionStatus;

    /// <summary>Cryptoki <c>CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CancelFunction;

    /// <summary>Cryptoki <c>CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong*, IntPtr, NativeCULong> C_WaitForSlotEvent;

    // ── v3.0 additions ────────────────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<void*, NativeCULong*, NativeCULong> C_GetInterfaceList;

    /// <summary>Cryptoki <c>CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS ulFlags)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong> C_GetInterface;

    /// <summary>Cryptoki <c>CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_LoginUser;

    /// <summary>Cryptoki <c>CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)</c> (v3.0+).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_SessionCancel;

    /// <summary>Cryptoki <c>CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_MessageEncryptInit;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_EncryptMessage;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong> C_EncryptMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_EncryptMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong> C_EncryptMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageEncryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_MessageDecryptInit;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_DecryptMessage;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, NativeCULong> C_DecryptMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_DecryptMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong, NativeCULong> C_DecryptMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageDecryptFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_MessageSignInit;

    /// <summary>Cryptoki <c>CK_RV C_SignMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignMessage;

    /// <summary>Cryptoki <c>CK_RV C_SignMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong> C_SignMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_SignMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_SignMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageSignFinal;

    /// <summary>Cryptoki <c>CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong> C_MessageVerifyInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessage(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyMessage;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessageBegin(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, NativeCULong> C_VerifyMessageBegin;

    /// <summary>Cryptoki <c>CK_RV C_VerifyMessageNext(...)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, IntPtr, NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifyMessageNext;

    /// <summary>Cryptoki <c>CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)</c> (v3.0).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_MessageVerifyFinal;

    // ── v3.2 additions ────────────────────────────────────────────────────────

    /// <summary>Cryptoki <c>CK_RV C_EncapsulateKey(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, byte*, NativeCULong*, NativeCULong*, NativeCULong> C_EncapsulateKey;

    /// <summary>Cryptoki <c>CK_RV C_DecapsulateKey(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_DecapsulateKey;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureInit(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignatureInit;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignature;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, NativeCULong> C_VerifySignatureUpdate;

    /// <summary>Cryptoki <c>CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_VerifySignatureFinal;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession, CK_FLAGS ulFlags, CK_FLAGS_PTR pulFlags)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong*, NativeCULong> C_GetSessionValidationFlags;

    /// <summary>Cryptoki <c>CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, void*, NativeCULong> C_AsyncComplete;

    /// <summary>Cryptoki <c>CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong*, NativeCULong> C_AsyncGetID;

    /// <summary>Cryptoki <c>CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulDataLen)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, byte*, NativeCULong, byte*, NativeCULong, NativeCULong> C_AsyncJoin;

    /// <summary>Cryptoki <c>CK_RV C_WrapKeyAuthenticated(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, NativeCULong, byte*, NativeCULong, byte*, NativeCULong*, NativeCULong> C_WrapKeyAuthenticated;

    /// <summary>Cryptoki <c>CK_RV C_UnwrapKeyAuthenticated(...)</c> (v3.2).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, void*, NativeCULong, byte*, NativeCULong, void*, NativeCULong, byte*, NativeCULong, NativeCULong*, NativeCULong> C_UnwrapKeyAuthenticated;

}
