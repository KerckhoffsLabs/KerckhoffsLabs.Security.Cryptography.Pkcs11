// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes an encryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The encryption mechanism</param>
    /// <param name="key">The handle of the encryption key</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_EncryptInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be encrypted</param>
    /// <param name="encryptedData">
    /// If set to null then the length of encrypted data is returned in "encryptedDataLen" parameter, without actually returning encrypted data.
    /// If not set to null then "encryptedDataLen" parameter must contain the lenght of encryptedData array and encrypted data is returned in "encryptedData" parameter.
    /// </param>
    /// <param name="encryptedDataLen">Location that holds the length in bytes of the encrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, out NativeCULong encryptedDataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Encrypt(session, data, encryptedData, out encryptedDataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be encrypted</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, out NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_EncryptUpdate(session, part, encryptedPart, out encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part encryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastEncryptedPart">
    /// If set to null then the length of last encrypted data part is returned in "lastEncryptedPartLen" parameter, without actually returning last encrypted data part.
    /// If not set to null then "lastEncryptedPartLen" parameter must contain the lenght of lastEncryptedPart array and last encrypted data part is returned in "lastEncryptedPart" parameter.
    /// </param>
    /// <param name="lastEncryptedPartLen">Location that holds the length of the last encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, out NativeCULong lastEncryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_EncryptFinal(session, lastEncryptedPart, out lastEncryptedPartLen);
        return rv.ToCKR();
    }
}
