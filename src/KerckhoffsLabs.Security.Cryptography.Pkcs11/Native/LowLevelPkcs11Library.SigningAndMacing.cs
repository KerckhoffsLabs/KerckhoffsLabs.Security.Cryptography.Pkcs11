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
    public unsafe CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var signInit = call.Functions.C_SignInit;
        if (signInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return signInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return signInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Signs data in a single part, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="signature">Receives the signature; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the signature's length: the module receives a NULL buffer.</param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public unsafe CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen)
    {
        using ModuleCall call = EnterModule();
        var sign = call.Functions.C_Sign;
        signatureLen = (NativeCULong)signature.Length;
        if (sign is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = &NonNullPinnable(signature))
        fixed (NativeCULong* lenPtr = &signatureLen)
            rv = sign(session, dataPtr, (NativeCULong)data.Length, lengthOnly ? null : sigPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, signatureLen, signature.Length);
    }

    /// <summary>
    /// Continues a multi-part signature operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        using ModuleCall call = EnterModule();
        var signUpdate = call.Functions.C_SignUpdate;
        if (signUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* partPtr = part)
            return signUpdate(session, partPtr, (NativeCULong)part.Length).ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part signature operation, returning the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Receives the signature; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the signature's length: the module receives a NULL buffer.</param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public unsafe CKR C_SignFinal(NativeCULong session, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen)
    {
        using ModuleCall call = EnterModule();
        var signFinal = call.Functions.C_SignFinal;
        signatureLen = (NativeCULong)signature.Length;
        if (signFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* sigPtr = &NonNullPinnable(signature))
        fixed (NativeCULong* lenPtr = &signatureLen)
            rv = signFinal(session, lengthOnly ? null : sigPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, signatureLen, signature.Length);
    }

    /// <summary>
    /// Initializes a signature operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="key">Handle of the signature key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var signRecoverInit = call.Functions.C_SignRecoverInit;
        if (signRecoverInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return signRecoverInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return signRecoverInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Signs data in a single operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="signature">Receives the signature; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the signature's length: the module receives a NULL buffer.</param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, bool lengthOnly, out NativeCULong signatureLen)
    {
        using ModuleCall call = EnterModule();
        var signRecover = call.Functions.C_SignRecover;
        signatureLen = (NativeCULong)signature.Length;
        if (signRecover is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = &NonNullPinnable(signature))
        fixed (NativeCULong* lenPtr = &signatureLen)
            rv = signRecover(session, dataPtr, (NativeCULong)data.Length, lengthOnly ? null : sigPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, signatureLen, signature.Length);
    }
}
