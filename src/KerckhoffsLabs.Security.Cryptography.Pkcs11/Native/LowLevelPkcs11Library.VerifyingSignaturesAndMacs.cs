// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initialize a signature-only verify operation, supplying the signature up front (PKCS#11 v3.2 §5.16.10). Data is fed via C_VerifySignature(Update) and the final check happens in C_VerifySignatureFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_VerifySignatureInit(session, ref mechanism, key, signature).ToCKR();
    }

    /// <summary>
    /// One-shot verify against the signature bound at init time (PKCS#11 v3.2 §5.16.11).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignature)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignature(session, data);
        return rv.ToCKR();
    }

    /// <summary>
    /// Feed a data chunk to a streaming signature-only verify (PKCS#11 v3.2 §5.16.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureUpdate)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignatureUpdate(session, part);
        return rv.ToCKR();
    }

    /// <summary>
    /// Conclude a streaming signature-only verify; returns CKR_OK on match, CKR_SIGNATURE_INVALID otherwise (PKCS#11 v3.2 §5.16.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignatureFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a verification operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_VerifyInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data that were signed</param>
    /// <param name="signature">Signature of data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Verify(session, data, signature);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyUpdate(session, part);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part verification operation, checking the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyFinal(session, signature);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a signature verification operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_VerifyRecoverInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <param name="data">
    /// If set to null then the length of recovered data is returned in "dataLen" parameter, without actually returning recovered data.
    /// If not set to null then "dataLen" parameter must contain the lenght of data array and recovered data is returned in "data" parameter.
    /// </param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID</returns>
    public CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, out NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyRecover(session, signature, data, out dataLen);
        return rv.ToCKR();
    }
}
