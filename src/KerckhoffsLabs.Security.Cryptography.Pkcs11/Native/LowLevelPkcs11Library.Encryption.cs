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
    public unsafe CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var encryptInit = call.Functions.C_EncryptInit;
        if (encryptInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return encryptInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return encryptInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be encrypted</param>
    /// <param name="encryptedData">Receives the encrypted data; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the encrypted data: the module receives a NULL buffer.</param>
    /// <param name="encryptedDataLen">Location that holds the length in bytes of the encrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, bool lengthOnly, out NativeCULong encryptedDataLen)
    {
        using ModuleCall call = EnterModule();
        var encrypt = call.Functions.C_Encrypt;
        encryptedDataLen = (NativeCULong)encryptedData.Length;
        if (encrypt is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = data)
        fixed (byte* outPtr = &NonNullPinnable(encryptedData))
        fixed (NativeCULong* lenPtr = &encryptedDataLen)
            rv = encrypt(session, inPtr, (NativeCULong)data.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, encryptedDataLen, encryptedData.Length);
    }

    /// <summary>
    /// Continues a multi-part encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be encrypted</param>
    /// <param name="encryptedPart">Receives the encrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the encrypted part: the module receives a NULL buffer.</param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen)
    {
        using ModuleCall call = EnterModule();
        var encryptUpdate = call.Functions.C_EncryptUpdate;
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        if (encryptUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = part)
        fixed (byte* outPtr = &NonNullPinnable(encryptedPart))
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            rv = encryptUpdate(session, inPtr, (NativeCULong)part.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, encryptedPartLen, encryptedPart.Length);
    }

    /// <summary>
    /// Finishes a multi-part encryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastEncryptedPart">Receives the last encrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the last encrypted part: the module receives a NULL buffer.</param>
    /// <param name="lastEncryptedPartLen">Location that holds the length of the last encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, bool lengthOnly, out NativeCULong lastEncryptedPartLen)
    {
        using ModuleCall call = EnterModule();
        var encryptFinal = call.Functions.C_EncryptFinal;
        lastEncryptedPartLen = (NativeCULong)lastEncryptedPart.Length;
        if (encryptFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(lastEncryptedPart))
        fixed (NativeCULong* lenPtr = &lastEncryptedPartLen)
            rv = encryptFinal(session, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, lastEncryptedPartLen, lastEncryptedPart.Length);
    }
}
