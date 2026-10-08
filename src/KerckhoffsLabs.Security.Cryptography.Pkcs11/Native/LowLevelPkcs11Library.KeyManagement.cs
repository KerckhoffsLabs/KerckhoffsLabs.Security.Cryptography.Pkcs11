using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// ML-KEM-style key encapsulation (PKCS#11 v3.2 §5.18.10). Takes an encapsulating public key, returns ciphertext + a handle to the encapsulated shared-secret key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        Span<byte> ciphertext, bool lengthOnly, out NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ciphertextLen = (NativeCULong)ciphertext.Length;
        using ModuleCall call = EnterModule();
        var encapsulateKey = call.Functions.C_EncapsulateKey;
        if (encapsulateKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(ciphertext))
        fixed (NativeCULong* lenPtr = &ciphertextLen)
        fixed (NativeCULong* keyPtr = &derivedKey)
        {
            rv = encapsulateKey(session, m, publicKey,
                templateBlock.Pointer, templateBlock.Count, lengthOnly ? null : outPtr, lenPtr, keyPtr).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, ciphertextLen, ciphertext.Length);
    }

    /// <summary>
    /// ML-KEM-style key decapsulation (PKCS#11 v3.2 §5.18.11). Reverses C_EncapsulateKey using the matching private key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey)
    {
        using ModuleCall call = EnterModule();
        var decapsulateKey = call.Functions.C_DecapsulateKey;
        if (decapsulateKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        fixed (byte* ctPtr = ciphertext)
        fixed (NativeCULong* keyPtr = &derivedKey)
        {
            return decapsulateKey(session, m, privateKey,
                templateBlock.Pointer, templateBlock.Count, ctPtr, (NativeCULong)ciphertext.Length, keyPtr).ToCKR();
        }
    }

    /// <summary>
    /// Wraps a key with authentication: the wrap is bound to the AAD bytes which must be supplied at unwrap (PKCS#11 v3.2 §5.18.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, bool lengthOnly, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        using ModuleCall call = EnterModule();
        var wrapKeyAuthenticated = call.Functions.C_WrapKeyAuthenticated;
        if (wrapKeyAuthenticated is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        CKR rv;
        fixed (byte* adPtr = associatedData)
        fixed (byte* outPtr = &NonNullPinnable(wrappedKey))
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
        {
            rv = wrapKeyAuthenticated(session, m, wrappingKey, key,
                adPtr, (NativeCULong)associatedData.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, wrappedKeyLen, wrappedKey.Length);
    }

    /// <summary>
    /// Unwrap counterpart to C_WrapKeyAuthenticated; verifies the AAD as part of the unwrap (PKCS#11 v3.2 §5.18.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var unwrapKeyAuthenticated = call.Functions.C_UnwrapKeyAuthenticated;
        if (unwrapKeyAuthenticated is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        fixed (byte* wrappedPtr = wrappedKey)
        fixed (byte* adPtr = associatedData)
        fixed (NativeCULong* keyPtr = &key)
        {
            return unwrapKeyAuthenticated(session, m, unwrappingKey,
                wrappedPtr, (NativeCULong)wrappedKey.Length, templateBlock.Pointer, templateBlock.Count,
                adPtr, (NativeCULong)associatedData.Length, keyPtr).ToCKR();
        }
    }

    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="template">The template for the new key or set of domain parameters</param>
    /// <param name="key">Location that receives the handle of the new key or set of domain parameters</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var generateKey = call.Functions.C_GenerateKey;
        if (generateKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        fixed (NativeCULong* keyPtr = &key)
            return generateKey(session, m, templateBlock.Pointer, templateBlock.Count, keyPtr).ToCKR();
    }

    /// <summary>
    /// Generates a public/private key pair, creating new key objects
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="publicKeyTemplate">The template for the public key</param>
    /// <param name="privateKeyTemplate">The template for the private key</param>
    /// <param name="publicKey">Location that receives the handle of the new public key</param>
    /// <param name="privateKey">Location that receives the handle of the new private key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        using ModuleCall call = EnterModule();
        var generateKeyPair = call.Functions.C_GenerateKeyPair;
        if (generateKeyPair is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> publicKeyTemplateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var publicKeyTemplateBlock = new NativeStructArray<CK_ATTRIBUTE>(publicKeyTemplate, nullWhenEmpty: true, publicKeyTemplateStack);
        Span<byte> privateKeyTemplateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var privateKeyTemplateBlock = new NativeStructArray<CK_ATTRIBUTE>(privateKeyTemplate, nullWhenEmpty: true, privateKeyTemplateStack);
        fixed (NativeCULong* pubKey = &publicKey)
        fixed (NativeCULong* privKey = &privateKey)
        {
            return generateKeyPair(session, m,
                publicKeyTemplateBlock.Pointer, publicKeyTemplateBlock.Count,
                privateKeyTemplateBlock.Pointer, privateKeyTemplateBlock.Count,
                pubKey, privKey).ToCKR();
        }
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKey">The handle of the wrapping key</param>
    /// <param name="key">The handle of the key to be wrapped</param>
    /// <param name="wrappedKey">Receives the wrapped key; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the wrapped key: the module receives a NULL buffer.</param>
    /// <param name="wrappedKeyLen">Location that receives the length of the wrapped key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_NOT_WRAPPABLE, CKR_KEY_SIZE_RANGE, CKR_KEY_UNEXTRACTABLE, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_WRAPPING_KEY_HANDLE_INVALID, CKR_WRAPPING_KEY_SIZE_RANGE, CKR_WRAPPING_KEY_TYPE_INCONSISTENT</returns>
    public unsafe CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, Span<byte> wrappedKey,
        bool lengthOnly, out NativeCULong wrappedKeyLen)
    {
        wrappedKeyLen = (NativeCULong)wrappedKey.Length;
        using ModuleCall call = EnterModule();
        var wrapKey = call.Functions.C_WrapKey;
        if (wrapKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(wrappedKey))
        fixed (NativeCULong* lenPtr = &wrappedKeyLen)
            rv = wrapKey(session, m, wrappingKey, key, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, wrappedKeyLen, wrappedKey.Length);
    }

    /// <summary>
    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Unwrapping mechanism</param>
    /// <param name="unwrappingKey">The handle of the unwrapping key</param>
    /// <param name="wrappedKey">Wrapped key</param>
    /// <param name="template">The template for the new key</param>
    /// <param name="key">Location that receives the handle of the unwrapped key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_SIZE_RANGE, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR_USER_NOT_LOGGED_IN, CKR_WRAPPED_KEY_INVALID, CKR_WRAPPED_KEY_LEN_RANGE</returns>
    public unsafe CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var unwrapKey = call.Functions.C_UnwrapKey;
        if (unwrapKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        fixed (byte* wrappedPtr = wrappedKey)
        fixed (NativeCULong* keyPtr = &key)
        {
            return unwrapKey(session, m, unwrappingKey, wrappedPtr, (NativeCULong)wrappedKey.Length,
                templateBlock.Pointer, templateBlock.Count, keyPtr).ToCKR();
        }
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key derivation mechanism</param>
    /// <param name="baseKey">The handle of the base key</param>
    /// <param name="template">The template for the new key</param>
    /// <param name="key">Location that receives the handle of the derived key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var deriveKey = call.Functions.C_DeriveKey;
        if (deriveKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        Span<byte> templateStack = stackalloc byte[NativeStructArray.StackBytes];
        using var templateBlock = new NativeStructArray<CK_ATTRIBUTE>(template, nullWhenEmpty: true, templateStack);
        fixed (NativeCULong* keyPtr = &key)
            return deriveKey(session, m, baseKey, templateBlock.Pointer, templateBlock.Count, keyPtr).ToCKR();
    }
}
