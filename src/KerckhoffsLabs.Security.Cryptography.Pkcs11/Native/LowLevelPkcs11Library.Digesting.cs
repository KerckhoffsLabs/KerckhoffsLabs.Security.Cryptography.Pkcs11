// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes a message-digesting operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The digesting mechanism</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_DigestInit(session, ref mechanism).ToCKR();
    }

    /// <summary>
    /// Digests data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be digested</param>
    /// <param name="digest">
    /// If set to null then the length of digest is returned in "digestLen" parameter, without actually returning digest.
    /// If not set to null then "digestLen" parameter must contain the lenght of digest array and digest is returned in "digest" parameter.
    /// </param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, out NativeCULong digestLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Digest(session, data, digest, out digestLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestUpdate(session, part);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation by digesting the value of a secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="key">The handle of the secret key to be digested</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE, CKR_KEY_SIZE_RANGE, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestKey(NativeCULong session, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestKey(session, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part message-digesting operation, returning the message digest
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="digest">
    /// If set to null then the length of digest is returned in "digestLen" parameter, without actually returning digest.
    /// If not set to null then "digestLen" parameter must contain the lenght of digest array and digest is returned in "digest" parameter.
    /// </param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestFinal(NativeCULong session, Span<byte> digest, out NativeCULong digestLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestFinal(session, digest, out digestLen);
        return rv.ToCKR();
    }
}
