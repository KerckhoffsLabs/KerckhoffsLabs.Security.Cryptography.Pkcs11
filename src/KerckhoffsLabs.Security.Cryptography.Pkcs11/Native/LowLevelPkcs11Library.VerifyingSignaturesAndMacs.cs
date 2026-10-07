using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initialize a signature-only verify operation, supplying the signature up front (PKCS#11 v3.2 §5.16.10). Data is fed via C_VerifySignature(Update) and the final check happens in C_VerifySignatureFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature)
    {
        using ModuleCall call = EnterModule();
        var verifySignatureInit = call.Functions.C_VerifySignatureInit;
        if (verifySignatureInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* sigPtr = signature)
        {
            if (Pkcs11Marshal.IsWindows)
            {
                CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
                return verifySignatureInit(session, &packed, key, sigPtr, (NativeCULong)signature.Length).ToCKR();
            }
            fixed (CK_MECHANISM* m = &mechanism)
                return verifySignatureInit(session, m, key, sigPtr, (NativeCULong)signature.Length).ToCKR();
        }
    }

    /// <summary>
    /// One-shot verify against the signature bound at init time (PKCS#11 v3.2 §5.16.11).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data)
    {
        using ModuleCall call = EnterModule();
        var verifySignature = call.Functions.C_VerifySignature;
        if (verifySignature is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* dataPtr = data)
            return verifySignature(session, dataPtr, (NativeCULong)data.Length).ToCKR();
    }

    /// <summary>
    /// Feed a data chunk to a streaming signature-only verify (PKCS#11 v3.2 §5.16.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        using ModuleCall call = EnterModule();
        var verifySignatureUpdate = call.Functions.C_VerifySignatureUpdate;
        if (verifySignatureUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* partPtr = part)
            return verifySignatureUpdate(session, partPtr, (NativeCULong)part.Length).ToCKR();
    }

    /// <summary>
    /// Conclude a streaming signature-only verify; returns CKR_OK on match, CKR_SIGNATURE_INVALID otherwise (PKCS#11 v3.2 §5.16.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifySignatureFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var verifySignatureFinal = call.Functions.C_VerifySignatureFinal;
        if (verifySignatureFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return verifySignatureFinal(session).ToCKR();
    }

    /// <summary>
    /// Initializes a verification operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var verifyInit = call.Functions.C_VerifyInit;
        if (verifyInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return verifyInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return verifyInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data that were signed</param>
    /// <param name="signature">Signature of data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public unsafe CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using ModuleCall call = EnterModule();
        var verify = call.Functions.C_Verify;
        if (verify is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return verify(session, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length).ToCKR();
    }

    /// <summary>
    /// Continues a multi-part verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        using ModuleCall call = EnterModule();
        var verifyUpdate = call.Functions.C_VerifyUpdate;
        if (verifyUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* partPtr = part)
            return verifyUpdate(session, partPtr, (NativeCULong)part.Length).ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part verification operation, checking the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public unsafe CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
    {
        using ModuleCall call = EnterModule();
        var verifyFinal = call.Functions.C_VerifyFinal;
        if (verifyFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* signaturePtr = signature)
            return verifyFinal(session, signaturePtr, (NativeCULong)signature.Length).ToCKR();
    }

    /// <summary>
    /// Initializes a signature verification operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var verifyRecoverInit = call.Functions.C_VerifyRecoverInit;
        if (verifyRecoverInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return verifyRecoverInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return verifyRecoverInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <param name="data">Receives the recovered data; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the recovered data: the module receives a NULL buffer.</param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID</returns>
    public unsafe CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, bool lengthOnly, out NativeCULong dataLen)
    {
        using ModuleCall call = EnterModule();
        var verifyRecover = call.Functions.C_VerifyRecover;
        dataLen = (NativeCULong)data.Length;
        if (verifyRecover is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* sigPtr = signature)
        fixed (byte* dataPtr = &NonNullPinnable(data))
        fixed (NativeCULong* lenPtr = &dataLen)
            rv = verifyRecover(session, sigPtr, (NativeCULong)signature.Length, lengthOnly ? null : dataPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, dataLen, data.Length);
    }
}
