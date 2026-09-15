// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes a signature operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="key">Handle of the signature key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED,CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_SignInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Signs data in a single part, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Sign(session, data, signature, out signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part signature operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignUpdate(session, part);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part signature operation, returning the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public CKR C_SignFinal(NativeCULong session, Span<byte> signature, out NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignFinal(session, signature, out signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a signature operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="key">Handle of the signature key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_SignRecoverInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Signs data in a single operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignRecover(session, data, signature, out signatureLen);
        return rv.ToCKR();
    }
}
