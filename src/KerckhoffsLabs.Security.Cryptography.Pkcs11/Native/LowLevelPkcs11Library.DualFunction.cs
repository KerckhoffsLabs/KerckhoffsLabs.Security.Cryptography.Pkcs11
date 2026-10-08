using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Continues multi-part digest and encryption operations, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be digested and encrypted</param>
    /// <param name="encryptedPart">Receives the encrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the encrypted part: the module receives a NULL buffer.</param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen)
    {
        using ModuleCall call = EnterModule();
        var digestEncryptUpdate = call.Functions.C_DigestEncryptUpdate;
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        if (digestEncryptUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = part)
        fixed (byte* outPtr = &NonNullPinnable(encryptedPart))
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            rv = digestEncryptUpdate(session, inPtr, (NativeCULong)part.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, encryptedPartLen, encryptedPart.Length);
    }

    /// <summary>
    /// Continues a multi-part combined decryption and digest operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">Receives the decrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the decrypted part: the module receives a NULL buffer.</param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen)
    {
        using ModuleCall call = EnterModule();
        var decryptDigestUpdate = call.Functions.C_DecryptDigestUpdate;
        partLen = (NativeCULong)part.Length;
        if (decryptDigestUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = encryptedPart)
        fixed (byte* outPtr = &NonNullPinnable(part))
        fixed (NativeCULong* lenPtr = &partLen)
            rv = decryptDigestUpdate(session, inPtr, (NativeCULong)encryptedPart.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, partLen, part.Length);
    }

    /// <summary>
    /// Continues a multi-part combined signature and encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be signed and encrypted</param>
    /// <param name="encryptedPart">Receives the encrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the encrypted part: the module receives a NULL buffer.</param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart, bool lengthOnly, out NativeCULong encryptedPartLen)
    {
        using ModuleCall call = EnterModule();
        var signEncryptUpdate = call.Functions.C_SignEncryptUpdate;
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        if (signEncryptUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = part)
        fixed (byte* outPtr = &NonNullPinnable(encryptedPart))
        fixed (NativeCULong* lenPtr = &encryptedPartLen)
            rv = signEncryptUpdate(session, inPtr, (NativeCULong)part.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, encryptedPartLen, encryptedPart.Length);
    }

    /// <summary>
    /// Continues a multi-part combined decryption and verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="part">Receives the decrypted part; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the decrypted part: the module receives a NULL buffer.</param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, bool lengthOnly, out NativeCULong partLen)
    {
        using ModuleCall call = EnterModule();
        var decryptVerifyUpdate = call.Functions.C_DecryptVerifyUpdate;
        partLen = (NativeCULong)part.Length;
        if (decryptVerifyUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = encryptedPart)
        fixed (byte* outPtr = &NonNullPinnable(part))
        fixed (NativeCULong* lenPtr = &partLen)
            rv = decryptVerifyUpdate(session, inPtr, (NativeCULong)encryptedPart.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, partLen, part.Length);
    }
}
