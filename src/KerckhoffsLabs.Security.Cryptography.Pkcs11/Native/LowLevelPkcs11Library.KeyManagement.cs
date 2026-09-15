// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// ML-KEM-style key encapsulation (PKCS#11 v3.2 §5.18.10). Takes an encapsulating public key, returns ciphertext + a handle to the encapsulated shared-secret key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncapsulateKey)
        {
            ciphertextLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        return _delegates.C_EncapsulateKey(session, ref mechanism, publicKey, template, ciphertext, out ciphertextLen, ref derivedKey).ToCKR();
    }

    /// <summary>
    /// ML-KEM-style key decapsulation (PKCS#11 v3.2 §5.18.11). Reverses C_EncapsulateKey using the matching private key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_DecapsulateKey)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_DecapsulateKey(session, ref mechanism, privateKey, template, ciphertext, ref derivedKey).ToCKR();
    }

    /// <summary>
    /// Wraps a key with authentication: the wrap is bound to the AAD bytes which must be supplied at unwrap (PKCS#11 v3.2 §5.18.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
        ReadOnlySpan<byte> associatedData, Span<byte> wrappedKey, out NativeCULong wrappedKeyLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_WrapKeyAuthenticated)
        {
            wrappedKeyLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        return _delegates.C_WrapKeyAuthenticated(session, ref mechanism, wrappingKey, key, associatedData, wrappedKey, out wrappedKeyLen).ToCKR();
    }

    /// <summary>
    /// Unwrap counterpart to C_WrapKeyAuthenticated; verifies the AAD as part of the unwrap (PKCS#11 v3.2 §5.18.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_UnwrapKeyAuthenticated)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_UnwrapKeyAuthenticated(session, ref mechanism, unwrappingKey, wrappedKey, template, associatedData, ref key).ToCKR();
    }

    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="template">The template for the new key or set of domain parameters</param>
    /// <param name="key">Location that receives the handle of the new key or set of domain parameters</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GenerateKey(session, ref mechanism, template, ref key).ToCKR();
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
    public CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate,
        ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, privateKeyTemplate, ref publicKey, ref privateKey).ToCKR();
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKey">The handle of the wrapping key</param>
    /// <param name="key">The handle of the key to be wrapped</param>
    /// <param name="wrappedKey">
    /// If set to null then the length of wrapped key is returned in "wrappedKeyLen" parameter, without actually returning wrapped key.
    /// If not set to null then "wrappedKeyLen" parameter must contain the lenght of wrappedKey array and wrapped key is returned in "wrappedKey" parameter.
    /// </param>
    /// <param name="wrappedKeyLen">Location that receives the length of the wrapped key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_NOT_WRAPPABLE, CKR_KEY_SIZE_RANGE, CKR_KEY_UNEXTRACTABLE, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_WRAPPING_KEY_HANDLE_INVALID, CKR_WRAPPING_KEY_SIZE_RANGE, CKR_WRAPPING_KEY_TYPE_INCONSISTENT</returns>
    public CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, Span<byte> wrappedKey,
        out NativeCULong wrappedKeyLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_WrapKey(session, ref mechanism, wrappingKey, key, wrappedKey, out wrappedKeyLen).ToCKR();
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
    public CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_UnwrapKey(session, ref mechanism, unwrappingKey, wrappedKey, template, ref key).ToCKR();
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
    public CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_DeriveKey(session, ref mechanism, baseKey, template, ref key).ToCKR();
    }
}
