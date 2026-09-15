// <auto-split-from Delegates.cs>

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the cryptoki dispatch boundary, and every unsafe region in it is one of " +
    "exactly three things C# permits nowhere else: invoking an unmanaged function pointer, pinning a managed " +
    "buffer for the duration of a native call, and taking the address of a blittable struct to pass as a " +
    "CK_*_PTR. There is no version of this file that satisfies the rule and still dispatches to a PKCS#11 " +
    "module. Suppressed at the type rather than per member so the rule keeps its value everywhere else: an " +
    "unsafe block appearing outside this boundary is still reported, and that is the case worth reviewing. " +
    "The safety argument does not rest on the suppression — every pointer is either pinned by a fixed " +
    "statement scoped to the call, or the address of a local, and every function pointer is null-checked by " +
    "ThrowIfUnbound before invocation. The dispatch table's binding is covered hermetically by " +
    "DelegatesLoaderTests, and the wrappers themselves by the full suite against SoftHSM2 and opencryptoki.")]
internal partial class Delegates
{
    /// <summary>Wrapper for <c>C_GenerateKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GenerateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_GenerateKey_Windows(session, &winMech, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_GenerateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_GenerateKey(session, m, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Wrapper for <c>C_GenerateKeyPair</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GenerateKeyPair_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winPub = ToWindowsTemplate(publicKeyTemplate);
            CK_ATTRIBUTE_Windows[]? winPriv = ToWindowsTemplate(privateKeyTemplate);
            fixed (CK_ATTRIBUTE_Windows* pub = winPub)
            fixed (CK_ATTRIBUTE_Windows* priv = winPriv)
            fixed (NativeCULong* pubK = &publicKey)
            fixed (NativeCULong* privK = &privateKey)
                return _fp.C_GenerateKeyPair_Windows(session, &winMech, pub, (NativeCULong)publicKeyTemplate.Length, priv, (NativeCULong)privateKeyTemplate.Length, pubK, privK);
        }

        ThrowIfUnbound(_fp.C_GenerateKeyPair);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* pub = publicKeyTemplate)
        fixed (CK_ATTRIBUTE* priv = privateKeyTemplate)
        fixed (NativeCULong* pubK = &publicKey)
        fixed (NativeCULong* privK = &privateKey)
            return _fp.C_GenerateKeyPair(session, m, pub, (NativeCULong)publicKeyTemplate.Length, priv, (NativeCULong)privateKeyTemplate.Length, pubK, privK);
    }

    /// <summary>Wrapper for <c>C_WrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        Span<byte> wrappedKey, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_WrapKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* wkPtr = wrappedKey)
            fixed (NativeCULong* lenPtr = &wrappedKeyLen)
                return _fp.C_WrapKey_Windows(session, &winMech, wrappingKey, key, wkPtr, lenPtr);
        }

        ThrowIfUnbound(_fp.C_WrapKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKey(session, m, wrappingKey, key, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_UnwrapKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (byte* wkPtr = wrappedKey)
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_UnwrapKey_Windows(session, &winMech, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_UnwrapKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKey(session, m, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Wrapper for <c>C_DeriveKey</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DeriveKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_DeriveKey_Windows(session, &winMech, baseKey, t, (NativeCULong)template.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_DeriveKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_DeriveKey(session, m, baseKey, t, (NativeCULong)template.Length, kPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncapsulateKey</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_EncapsulateKey => _fp.C_EncapsulateKey is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecapsulateKey</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_DecapsulateKey => _fp.C_DecapsulateKey is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_WrapKeyAuthenticated => _fp.C_WrapKeyAuthenticated is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_UnwrapKeyAuthenticated => _fp.C_UnwrapKeyAuthenticated is not null;

    // ── v3.2 PQC / signature / async / authenticated-wrap wrappers ───────────────

    /// <summary>Wrapper for <c>C_EncapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ciphertextLen = (NativeCULong)ciphertext.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_EncapsulateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* ctPtr = ciphertext)
            fixed (NativeCULong* ctLenPtr = &ciphertextLen)
            fixed (NativeCULong* dkPtr = &derivedKey)
                return _fp.C_EncapsulateKey_Windows(session, &winMech, publicKey, t, (NativeCULong)template.Length, ctPtr, ctLenPtr, dkPtr);
        }

        ThrowIfUnbound(_fp.C_EncapsulateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_EncapsulateKey(session, m, publicKey, t, (NativeCULong)template.Length, ctPtr, ctLenPtr, dkPtr);
    }

    /// <summary>Wrapper for <c>C_DecapsulateKey</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DecapsulateKey_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* ctPtr = ciphertext)
            fixed (NativeCULong* dkPtr = &derivedKey)
                return _fp.C_DecapsulateKey_Windows(session, &winMech, privateKey, t, (NativeCULong)template.Length, ctPtr, (NativeCULong)ciphertext.Length, dkPtr);
        }

        ThrowIfUnbound(_fp.C_DecapsulateKey);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* dkPtr = &derivedKey)
            return _fp.C_DecapsulateKey(session, m, privateKey, t, (NativeCULong)template.Length, ctPtr, (NativeCULong)ciphertext.Length, dkPtr);
    }

    /// <summary>Wrapper for <c>C_WrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_WrapKeyAuthenticated_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* adPtr = associatedData)
            fixed (byte* wkPtr = wrappedKey)
            fixed (NativeCULong* lenPtr = &wrappedKeyLen)
                return _fp.C_WrapKeyAuthenticated_Windows(session, &winMech, wrappingKey, key, adPtr, (NativeCULong)associatedData.Length, wkPtr, lenPtr);
        }

        ThrowIfUnbound(_fp.C_WrapKeyAuthenticated);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* adPtr = associatedData)
        fixed (byte* wkPtr = wrappedKey)
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            return _fp.C_WrapKeyAuthenticated(session, m, wrappingKey, key, adPtr, (NativeCULong)associatedData.Length, wkPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_UnwrapKeyAuthenticated</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey,
        ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_UnwrapKeyAuthenticated_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (byte* wkPtr = wrappedKey)
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (byte* adPtr = associatedData)
            fixed (NativeCULong* kPtr = &key)
                return _fp.C_UnwrapKeyAuthenticated_Windows(session, &winMech, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, adPtr, (NativeCULong)associatedData.Length, kPtr);
        }

        ThrowIfUnbound(_fp.C_UnwrapKeyAuthenticated);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* wkPtr = wrappedKey)
        fixed (CK_ATTRIBUTE* t = template)
        fixed (byte* adPtr = associatedData)
        fixed (NativeCULong* kPtr = &key)
            return _fp.C_UnwrapKeyAuthenticated(session, m, unwrappingKey, wkPtr, (NativeCULong)wrappedKey.Length, t, (NativeCULong)template.Length, adPtr, (NativeCULong)associatedData.Length, kPtr);
    }
}
