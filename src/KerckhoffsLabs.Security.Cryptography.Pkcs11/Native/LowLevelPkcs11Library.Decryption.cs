// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes a decryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The decryption mechanism</param>
    /// <param name="key">The handle of the decryption key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_DecryptInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Decrypts encrypted data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedData">Encrypted data</param>
    /// <param name="data">
    /// If set to null then the length of decrypted data is returned in "dataLen" parameter, without actually returning decrypted data.
    /// If not set to null then "dataLen" parameter must contain the lenght of data array and decrypted data is returned in "data" parameter.
    /// </param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Decrypt(session, encryptedData, data, out dataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part decryption operation, processing another encrypted data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptUpdate(session, encryptedPart, part, out partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part decryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastPart">
    /// If set to null then the length of last decrypted data part is returned in "lastPartLen" parameter, without actually returning last decrypted data part.
    /// If not set to null then "lastPartLen" parameter must contain the lenght of lastPart array and last decrypted data part is returned in "lastPart" parameter.
    /// </param>
    /// <param name="lastPartLen">Location that holds the length of the last decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptFinal(NativeCULong session, Span<byte> lastPart, out NativeCULong lastPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptFinal(session, lastPart, out lastPartLen);
        return rv.ToCKR();
    }
}
