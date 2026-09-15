// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Continues multi-part digest and encryption operations, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be digested and encrypted</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestEncryptUpdate(session, part, encryptedPart, out encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined decryption and digest operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptDigestUpdate(session, encryptedPart, part, out partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined signature and encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be signed and encrypted</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignEncryptUpdate(session, part, encryptedPart, out encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined decryption and verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptVerifyUpdate(session, encryptedPart, part, out partLen);
        return rv.ToCKR();
    }
}
