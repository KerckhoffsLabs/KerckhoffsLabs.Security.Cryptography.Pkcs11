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
    public unsafe CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var decryptInit = call.Functions.C_DecryptInit;
        if (decryptInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return decryptInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return decryptInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// Decrypts encrypted data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedData">Encrypted data</param>
    /// <param name="data">Receives the decrypted data; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the decrypted data: the module receives a NULL buffer.</param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, bool lengthOnly, out NativeCULong dataLen)
    {
        using ModuleCall call = EnterModule();
        var decrypt = call.Functions.C_Decrypt;
        dataLen = (NativeCULong)data.Length;
        if (decrypt is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = encryptedData)
        fixed (byte* outPtr = &NonNullPinnable(data))
        fixed (NativeCULong* lenPtr = &dataLen)
            rv = decrypt(session, inPtr, (NativeCULong)encryptedData.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, dataLen, data.Length);
    }

    /// <summary>
    /// Continues a multi-part decryption operation, processing another encrypted data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">Receives the decrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the decrypted part: the module receives a NULL buffer.</param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen)
    {
        using ModuleCall call = EnterModule();
        var decryptUpdate = call.Functions.C_DecryptUpdate;
        partLen = (NativeCULong)part.Length;
        if (decryptUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = encryptedPart)
        fixed (byte* outPtr = &NonNullPinnable(part))
        fixed (NativeCULong* lenPtr = &partLen)
            rv = decryptUpdate(session, inPtr, (NativeCULong)encryptedPart.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, partLen, part.Length);
    }

    /// <summary>
    /// Finishes a multi-part decryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastPart">Receives the last decrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the last decrypted part: the module receives a NULL buffer.</param>
    /// <param name="lastPartLen">Location that holds the length of the last decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_DecryptFinal(NativeCULong session, Span<byte> lastPart, bool lengthOnly, out NativeCULong lastPartLen)
    {
        using ModuleCall call = EnterModule();
        var decryptFinal = call.Functions.C_DecryptFinal;
        lastPartLen = (NativeCULong)lastPart.Length;
        if (decryptFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(lastPart))
        fixed (NativeCULong* lenPtr = &lastPartLen)
            rv = decryptFinal(session, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, lastPartLen, lastPart.Length);
    }
}
