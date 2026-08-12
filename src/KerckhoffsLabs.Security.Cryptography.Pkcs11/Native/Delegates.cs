using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;


/// <summary>
/// Holds delegates for all PKCS#11 functions
/// </summary>
internal partial class Delegates
{
    /// <summary>
    /// Typed function pointer table. Populated by Initialize / TryLoadV30Symbols /
    /// TryLoadFromGetInterface; every cryptoki function is dispatched through an entry
    /// here plus a wrapper method on this class.
    /// </summary>
    internal readonly FunctionPointers _fp = new();

    /// <summary>Native cryptoki bootstrap symbol name, used for export lookup and error context (S1192).</summary>
    private const string GetFunctionListSymbol = "C_GetFunctionList";

    /// <summary>
    /// Guards a wrapper against a function the loaded module never provided. The cryptoki name
    /// comes from the calling wrapper — each one is named after the function it dispatches to —
    /// so the error context cannot drift from the pointer being tested.
    /// </summary>
    /// <param name="function">Dispatch-table entry; <see langword="null"/> when unbound.</param>
    /// <param name="name">Supplied by the compiler. Do not pass explicitly.</param>
    private static unsafe void ThrowIfUnbound(void* function, [CallerMemberName] string name = "")
    {
        if (function is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, name);
    }

    /// <summary>
    /// Copies a unified attribute template into the Pack=1 Windows layout for the duration of a
    /// single call. Null in, null out: a null template is a legitimate cryptoki argument.
    /// </summary>
    private static CK_ATTRIBUTE_Windows[]? ToWindowsTemplate(ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (template.IsEmpty)
            return null;

        var packed = new CK_ATTRIBUTE_Windows[template.Length];
        for (int i = 0; i < template.Length; i++)
            packed[i] = CK_ATTRIBUTE_Windows.FromUnified(in template[i]);
        return packed;
    }

    /// <summary>Wrapper for <c>C_Initialize</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Initialize(IntPtr pInitArgs);

    /// <summary>Wrapper for <c>C_Finalize</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Finalize(IntPtr reserved);

    /// <summary>Wrapper for <c>C_GetInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetInfo([FilledByToken] ref CK_INFO info);

    /// <summary>Wrapper for <c>C_GetFunctionList</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>Deliberately not <c>partial</c>: <c>out IntPtr</c> has no native mapping DispatchModel
    /// knows (it is the bootstrap call that hands back the address every other function pointer is
    /// bound from, not a cryptoki-shaped argument). The generator still emits the field and binding
    /// from the attribute; only this body is hand-written.</remarks>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe NativeCULong C_GetFunctionList(out IntPtr functionList)
    {
        ThrowIfUnbound(_fp.C_GetFunctionList);
        IntPtr local = IntPtr.Zero;
        NativeCULong rv = _fp.C_GetFunctionList(&local);
        functionList = local;
        return rv;
    }

    /// <summary>Wrapper for <c>C_GetSlotList</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count);

    /// <summary>Wrapper for <c>C_GetSlotInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetSlotInfo(NativeCULong slotId, [FilledByToken] ref CK_SLOT_INFO info);

    /// <summary>Wrapper for <c>C_GetTokenInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetTokenInfo(NativeCULong slotId, [FilledByToken] ref CK_TOKEN_INFO info);

    /// <summary>Wrapper for <c>C_GetMechanismList</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GetMechanismList(NativeCULong slotId, NativeCULong[]? mechanismList, ref NativeCULong count);

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, [FilledByToken] ref CK_MECHANISM_INFO info);

    /// <summary>Wrapper for <c>C_InitToken</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, [Unsized] ReadOnlySpan<byte> label);

    /// <summary>Wrapper for <c>C_InitPIN</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin);

    /// <summary>Wrapper for <c>C_SetPIN</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin);

    /// <summary>Wrapper for <c>C_OpenSession</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session);

    /// <summary>Wrapper for <c>C_CloseSession</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_CloseSession(NativeCULong session);

    /// <summary>Wrapper for <c>C_CloseAllSessions</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_CloseAllSessions(NativeCULong slotId);

    /// <summary>Wrapper for <c>C_GetSessionInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetSessionInfo(NativeCULong session, [FilledByToken] ref CK_SESSION_INFO info);

    /// <summary>Wrapper for <c>C_GetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GetOperationState(NativeCULong session, Span<byte> operationState, out NativeCULong operationStateLen);

    /// <summary>Wrapper for <c>C_SetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey,
        NativeCULong authenticationKey);

    /// <summary>Wrapper for <c>C_Login</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin);

    /// <summary>Wrapper for <c>C_Logout</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Logout(NativeCULong session);

    /// <summary>Wrapper for <c>C_CreateObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId);

    /// <summary>Wrapper for <c>C_CopyObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong newObjectId);

    /// <summary>Wrapper for <c>C_DestroyObject</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId);

    /// <summary>Wrapper for <c>C_GetObjectSize</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size);

    /// <summary>Wrapper for <c>C_GetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template);

    /// <summary>Wrapper for <c>C_SetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template);

    /// <summary>Wrapper for <c>C_FindObjectsInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template);

    /// <summary>Wrapper for <c>C_FindObjects</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount);

    /// <summary>Wrapper for <c>C_FindObjectsFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_FindObjectsFinal(NativeCULong session);

    /// <summary>Wrapper for <c>C_EncryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_Encrypt</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, out NativeCULong encryptedDataLen);

    /// <summary>Wrapper for <c>C_EncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen);

    /// <summary>Wrapper for <c>C_EncryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, out NativeCULong lastEncryptedPartLen);

    /// <summary>Wrapper for <c>C_DecryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_Decrypt</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen);

    /// <summary>Wrapper for <c>C_DecryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen);

    /// <summary>Wrapper for <c>C_DecryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DecryptFinal(NativeCULong session, Span<byte> lastPart, out NativeCULong lastPartLen);

    /// <summary>Wrapper for <c>C_DigestInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism);

    /// <summary>Wrapper for <c>C_Digest</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, out NativeCULong digestLen);

    /// <summary>Wrapper for <c>C_DigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part);

    /// <summary>Wrapper for <c>C_DigestKey</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DigestKey(NativeCULong session, NativeCULong key);

    /// <summary>Wrapper for <c>C_DigestFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DigestFinal(NativeCULong session, Span<byte> digest, out NativeCULong digestLen);

    /// <summary>Wrapper for <c>C_SignInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_Sign</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen);

    /// <summary>Wrapper for <c>C_SignUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part);

    /// <summary>Wrapper for <c>C_SignFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SignFinal(NativeCULong session, Span<byte> signature, out NativeCULong signatureLen);

    /// <summary>Wrapper for <c>C_SignRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_SignRecover</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen);

    /// <summary>Wrapper for <c>C_VerifyInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_Verify</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>Wrapper for <c>C_VerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part);

    /// <summary>Wrapper for <c>C_VerifyFinal</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature);

    /// <summary>Wrapper for <c>C_VerifyRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_VerifyRecover</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, out NativeCULong dataLen);

    /// <summary>Wrapper for <c>C_DigestEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen);

    /// <summary>Wrapper for <c>C_DecryptDigestUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part,
        out NativeCULong partLen);

    /// <summary>Wrapper for <c>C_SignEncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen);

    /// <summary>Wrapper for <c>C_DecryptVerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part,
        out NativeCULong partLen);

    /// <summary>Wrapper for <c>C_GenerateKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key);

    /// <summary>Wrapper for <c>C_GenerateKeyPair</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey);

    /// <summary>Wrapper for <c>C_WrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        Span<byte> wrappedKey, out NativeCULong wrappedKeyLen);

    /// <summary>Wrapper for <c>C_UnwrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key);

    /// <summary>Wrapper for <c>C_DeriveKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V240, WindowsLayout = true)]
    public unsafe partial NativeCULong C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key);

    /// <summary>Wrapper for <c>C_SeedRandom</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed);

    /// <summary>Wrapper for <c>C_GenerateRandom</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GenerateRandom(NativeCULong session, [FillsToCapacity] Span<byte> randomData);

    /// <summary>Wrapper for <c>C_GetFunctionStatus</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_GetFunctionStatus(NativeCULong session);

    /// <summary>Wrapper for <c>C_CancelFunction</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_CancelFunction(NativeCULong session);

    /// <summary>Wrapper for <c>C_WaitForSlotEvent</c>. Matches the prior delegate signature exactly.</summary>
    [Pkcs11Function(Cryptoki.V240)]
    public unsafe partial NativeCULong C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved);

    /// <summary>Wrapper for <c>C_LoginUser</c> (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username);

    /// <summary>Wrapper for <c>C_SessionCancel</c> (PKCS#11 v3.0). Throws <see cref="Pkcs11Exception"/> if the loaded library is v2.40 or does not export the symbol.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_SessionCancel(NativeCULong session, NativeCULong flags);

    /// <summary>Wrapper for <c>C_GetInterfaceList</c> (PKCS#11 v3.0). Two-call idiom: pass <c>null</c> to get the count.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.
    /// Deliberately not <c>partial</c>: the null-array two-call idiom branches on
    /// <c>interfaces is null</c> to skip pinning and pass a null pointer for the count-only call,
    /// which is not one of the uniform per-parameter shapes DispatchEmitter emits. The generator
    /// still emits the field, the Windows twin field, and the binding from the attribute; only
    /// this body is hand-written.</remarks>
    [Pkcs11Function(Cryptoki.V300, WindowsLayout = true)]
    public unsafe NativeCULong C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetInterfaceList_Windows);
            if (interfaces is null)
            {
                fixed (NativeCULong* c = &count)
                    return _fp.C_GetInterfaceList_Windows(null, c);
            }

            var winList = new CK_INTERFACE_Windows[interfaces.Length];
            NativeCULong winRv;
            fixed (CK_INTERFACE_Windows* list = winList)
            fixed (NativeCULong* c = &count)
                winRv = _fp.C_GetInterfaceList_Windows(list, c);
            if (winRv.ToCKR() == CKR.CKR_OK)
                for (int i = 0; i < interfaces.Length; i++)
                    interfaces[i] = winList[i].ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetInterfaceList);
        fixed (CK_INTERFACE* list = interfaces)
        fixed (NativeCULong* c = &count)
            return _fp.C_GetInterfaceList(list, c);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetInterface</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_GetInterface => _fp.C_GetInterface is not null;

    /// <summary>
    /// Wrapper for <c>C_GetInterface</c> (PKCS#11 v3.0). Requests the interface named
    /// <paramref name="interfaceName"/> (a NUL-terminated UTF-8 string, or <c>null</c> for the module's
    /// default interface) and reads back the token-owned <see cref="CK_INTERFACE"/> descriptor (the
    /// version argument is always passed as <c>NULL</c> — any version). The returned struct is read via
    /// <see cref="UnmanagedMemory.Read{T}"/>, which applies the correct platform layout, so no Pack=1
    /// sibling wrapper is needed (unlike <c>C_GetInterfaceList</c>, the token owns the memory and we
    /// only read it).
    /// </summary>
    public unsafe NativeCULong C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface)
    {
        iface = default;
        ThrowIfUnbound(_fp.C_GetInterface);

        IntPtr interfacePtr;
        NativeCULong rv;
        fixed (byte* namePtr = interfaceName)
            rv = _fp.C_GetInterface(namePtr, IntPtr.Zero, &interfacePtr, flags);

        if (rv.ToCKR() == CKR.CKR_OK && interfacePtr != IntPtr.Zero)
            iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        return rv;
    }

    // Has* availability properties for the optional v3.0/v3.2 functions below are generated —
    // see Delegates.Binding.g.cs.

    // ── Message-AEAD family wrappers (v3.0) ──────────────────────────────────────

    /// <summary>Wrapper for <c>C_MessageEncryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V300, WindowsLayout = true)]
    public unsafe partial NativeCULong C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_EncryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out NativeCULong ciphertextLen);

    /// <summary>Wrapper for <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData);

    /// <summary>Wrapper for <c>C_EncryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, out NativeCULong ciphertextPartLen, NativeCULong flags);

    /// <summary>Wrapper for <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_MessageEncryptFinal(NativeCULong session);

    /// <summary>Wrapper for <c>C_MessageDecryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V300, WindowsLayout = true)]
    public unsafe partial NativeCULong C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_DecryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out NativeCULong plaintextLen);

    /// <summary>Wrapper for <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData);

    /// <summary>Wrapper for <c>C_DecryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, out NativeCULong plaintextPartLen, NativeCULong flags);

    /// <summary>Wrapper for <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_MessageDecryptFinal(NativeCULong session);

    /// <summary>Wrapper for <c>C_MessageSignInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V300, WindowsLayout = true)]
    public unsafe partial NativeCULong C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_SignMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen);

    /// <summary>Wrapper for <c>C_SignMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);

    /// <summary>Wrapper for <c>C_SignMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen);

    /// <summary>Wrapper for <c>C_MessageSignFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_MessageSignFinal(NativeCULong session);

    /// <summary>Wrapper for <c>C_MessageVerifyInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V300, WindowsLayout = true)]
    public unsafe partial NativeCULong C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key);

    /// <summary>Wrapper for <c>C_VerifyMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature);

    /// <summary>Wrapper for <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen);

    /// <summary>Wrapper for <c>C_VerifyMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature);

    /// <summary>Wrapper for <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V300)]
    public unsafe partial NativeCULong C_MessageVerifyFinal(NativeCULong session);

    // ── v3.2 PQC / signature / async / authenticated-wrap wrappers ───────────────

    /// <summary>Wrapper for <c>C_EncapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey);

    /// <summary>Wrapper for <c>C_DecapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey);

    /// <summary>Wrapper for <c>C_VerifySignatureInit</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature);

    /// <summary>Wrapper for <c>C_VerifySignature</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data);

    /// <summary>Wrapper for <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part);

    /// <summary>Wrapper for <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_VerifySignatureFinal(NativeCULong session);

    /// <summary>Wrapper for <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags);

    /// <summary>Wrapper for <c>C_AsyncComplete</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_AsyncComplete(NativeCULong session, [Unsized] ReadOnlySpan<byte> functionName, [FilledByToken] ref CK_ASYNC_DATA result);

    /// <summary>Wrapper for <c>C_AsyncGetID</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_AsyncGetID(NativeCULong session, [Unsized] ReadOnlySpan<byte> functionName, ref NativeCULong id);

    /// <summary>Wrapper for <c>C_AsyncJoin</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    [Pkcs11Function(Cryptoki.V320)]
    public unsafe partial NativeCULong C_AsyncJoin(NativeCULong session, [Unsized] ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data);

    /// <summary>Wrapper for <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen);

    /// <summary>Wrapper for <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    [Pkcs11Function(Cryptoki.V320, WindowsLayout = true)]
    public unsafe partial NativeCULong C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key);

    /// <summary>
    /// Initializes a new instance of <see cref="Delegates"/>. Function pointers are
    /// acquired via <c>C_GetFunctionList</c> against the dynamically loaded library
    /// when <paramref name="libraryHandle"/> is non-zero, or against the host
    /// executable's own symbol table otherwise (a statically-linked module).
    /// </summary>
    /// <param name="libraryHandle">Handle to the dynamically loaded PKCS#11 library,
    /// or <see cref="IntPtr.Zero"/> for a statically-linked library.</param>
    internal Delegates(IntPtr libraryHandle)
        // A statically-linked module's exports live in the entry-point module, which
        // GetMainProgramHandle() resolves against on CoreCLR and Native AOT alike. That makes the
        // static path the ordinary load sequence over a different handle rather than a separate
        // bootstrap: same C_GetFunctionList entry, same best-effort v3.0/v3.2 binding, same
        // graceful degradation for exports a v2.40-only module does not provide.
        => Load(ResolverFor(libraryHandle != IntPtr.Zero
            ? libraryHandle
            : NativeLibrary.GetMainProgramHandle()));

    /// <summary>
    /// Initializes the dispatch table through an export resolver instead of an OS library
    /// handle. This is the hermetic-test seam: production goes through
    /// <see cref="Delegates(IntPtr)"/>, whose resolver wraps <see cref="NativeLibrary.TryGetExport"/>;
    /// tests supply a resolver returning managed <c>[UnmanagedCallersOnly]</c> stubs and
    /// synthetic function-list tables, so the real bootstrap / version-dispatch / slot-binding
    /// logic runs without any native module.
    /// </summary>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal Delegates(Func<string, IntPtr> resolveExport) => Load(resolveExport);

    /// <summary>Dynamic-load sequence: v2.40 bootstrap, then best-effort v3.0/v3.2 binding.</summary>
    private void Load(Func<string, IntPtr> resolveExport)
    {
        InitializeWithGetFunctionList(resolveExport);
        // Best-effort load of v3.0 functions via direct symbol lookup. The full
        // C_GetInterface-based loader path lives in Pkcs11Library / bucket E.
        TryLoadV30Symbols(resolveExport);
    }

    /// <summary>Export resolver over an OS library handle (returns Zero for missing exports).</summary>
    private static Func<string, IntPtr> ResolverFor(IntPtr libraryHandle)
        => name => NativeLibrary.TryGetExport(libraryHandle, name, out IntPtr address) ? address : IntPtr.Zero;

    /// <summary>Resolves <paramref name="name"/> and reports whether it is present.</summary>
    private static bool TryResolve(Func<string, IntPtr> resolveExport, string name, out IntPtr address)
    {
        address = resolveExport(name);
        return address != IntPtr.Zero;
    }

    /// <summary>
    /// Best-effort: bind v3.0 function pointers. Preferred path is C_GetInterface
    /// (v3.0 §5.4.5) which yields a typed CK_FUNCTION_LIST_3_0 carrying every v2.40
    /// pointer plus the v3.0 additions. Fallback path: per-symbol NativeLibrary lookup
    /// against the dynamically loaded library — handles v2.40 tokens (delegates stay
    /// <see langword="null"/>) and v3.0 tokens that export individual symbols but
    /// don't publish the interface table.
    /// </summary>
    private void TryLoadV30Symbols(Func<string, IntPtr> resolveExport)
    {
        // Preferred: ask the library for its v3.0 interface table.
        if (TryLoadFromGetInterface(resolveExport))
            return;

        // Fallback: per-symbol lookup. Works for libraries that export the v3.0
        // functions as plain symbols even though they don't expose C_GetInterface.
        BindV3SymbolsFromResolver(resolveExport);
    }

    /// <summary>
    /// Tries the preferred v3.0 loader path: call C_GetInterface to obtain the default
    /// "PKCS 11" interface, then read its function table as <see cref="CK_FUNCTION_LIST_3_0"/>
    /// and bind every v3.0 delegate from the table. Returns true on success, false if
    /// C_GetInterface is unavailable / fails / returns a non-3.x version, leaving the
    /// caller to use the per-symbol fallback.
    /// </summary>
    private bool TryLoadFromGetInterface(Func<string, IntPtr> resolveExport)
    {
        if (!TryResolve(resolveExport, "C_GetInterface", out IntPtr getInterfaceRawPtr))
            return false;
        unsafe { _fp.C_GetInterface = (delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)getInterfaceRawPtr; }

        if (!TryGetDefaultInterfaceFunctionList(out IntPtr functionList, out CK_VERSION version))
            return false;

        BindV30FunctionList(UnmanagedMemory.Read<CK_FUNCTION_LIST_3_0>(functionList));

        // v3.2 token: re-read the function table as CK_FUNCTION_LIST_3_2 and bind
        // the 12 v3.2 additions on top of the v3.0 bindings.
        if (version.Minor >= 2)
            BindV32FunctionList(UnmanagedMemory.Read<CK_FUNCTION_LIST_3_2>(functionList));

        return true;
    }

    /// <summary>
    /// Asks the already-bound C_GetInterface for the default interface (null name, null
    /// version, flags = 0) and validates the table it hands back. Yields the function-list
    /// pointer and its CK_VERSION header only for a v3.x table; returns false — with
    /// <paramref name="functionList"/> left at <see cref="IntPtr.Zero"/> — when the call
    /// throws, fails, or returns a v2.40 table the v3.0 binders must not read.
    /// </summary>
    private bool TryGetDefaultInterfaceFunctionList(out IntPtr functionList, out CK_VERSION version)
    {
        functionList = IntPtr.Zero;
        version = default;

        IntPtr interfacePtr;
        NativeCULong rv;
        try
        {
            unsafe { rv = _fp.C_GetInterface(null, IntPtr.Zero, &interfacePtr, new NativeCULong(0)); }
        }
        catch
        {
            return false;
        }

        if (rv.ToCKR() != CKR.CKR_OK || interfacePtr == IntPtr.Zero)
            return false;

        CK_INTERFACE iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        if (iface.FunctionList == IntPtr.Zero)
            return false;

        // The function-list pointer can be either CK_FUNCTION_LIST (v2.40) or
        // CK_FUNCTION_LIST_3_0 (v3.0+). The CK_VERSION header at offset 0 distinguishes
        // them. Read just the version first to decide.
        version = UnmanagedMemory.Read<CK_VERSION>(iface.FunctionList);
        if (version.Major < 3)
            return false;

        functionList = iface.FunctionList;
        return true;
    }

    // Has* / Bind* for the optional v3.0/v3.2 functions above, and BindV30FunctionList /
    // BindV32FunctionList / BindV3SymbolsFromResolver, are generated — see Delegates.Binding.g.cs.

    /// <summary>
    /// Get delegates with C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
    /// </summary>
    /// <param name="resolveExport">Export resolver for the PKCS#11 library</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
        Justification = "Calling the module's C_GetFunctionList export requires an unmanaged function-pointer " +
        "invocation, which C# only permits in unsafe code. Every outcome is guarded (missing symbol, non-OK CKR, " +
        "null function-list pointer each throw), the struct read goes through the platform-dispatching " +
        "UnmanagedMemory.Read, and which native module to trust is the consumer's explicit choice. " +
        "The path is covered hermetically by DelegatesLoaderTests, including its failure arms.")]
    private unsafe void InitializeWithGetFunctionList(Func<string, IntPtr> resolveExport)
    {
        // Mirrors NativeLibrary.GetExport's contract: a missing bootstrap symbol is fatal.
        if (!TryResolve(resolveExport, GetFunctionListSymbol, out IntPtr getFunctionListPtr))
            throw new EntryPointNotFoundException(
                $"Unable to find an entry point named '{GetFunctionListSymbol}' in the PKCS#11 library.");
        var getFunctionList = (delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)getFunctionListPtr;

        IntPtr functionList = IntPtr.Zero;

        CKR returnValue = getFunctionList(&functionList).ToCKR();
        Pkcs11Exception.ThrowIfError(returnValue, GetFunctionListSymbol);
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        CK_FUNCTION_LIST funcList = UnmanagedMemory.Read<CK_FUNCTION_LIST>(functionList);
        Initialize(funcList);
    }
}
