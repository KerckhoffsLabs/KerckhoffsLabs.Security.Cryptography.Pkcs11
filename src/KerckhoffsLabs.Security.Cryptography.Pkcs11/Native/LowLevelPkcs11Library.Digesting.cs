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
    public unsafe CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        using ModuleCall call = EnterModule();
        var digestInit = call.Functions.C_DigestInit;
        if (digestInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return digestInit(session, &packed).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return digestInit(session, m).ToCKR();
    }

    /// <summary>
    /// Digests data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be digested</param>
    /// <param name="digest">Receives the digest; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the digest: the module receives a NULL buffer.</param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, bool lengthOnly, out NativeCULong digestLen)
    {
        using ModuleCall call = EnterModule();
        var digestFunction = call.Functions.C_Digest;
        digestLen = (NativeCULong)digest.Length;
        if (digestFunction is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* inPtr = data)
        fixed (byte* outPtr = &NonNullPinnable(digest))
        fixed (NativeCULong* lenPtr = &digestLen)
            rv = digestFunction(session, inPtr, (NativeCULong)data.Length, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, digestLen, digest.Length);
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        using ModuleCall call = EnterModule();
        var digestUpdate = call.Functions.C_DigestUpdate;
        if (digestUpdate is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* partPtr = part)
            return digestUpdate(session, partPtr, (NativeCULong)part.Length).ToCKR();
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation by digesting the value of a secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="key">The handle of the secret key to be digested</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE, CKR_KEY_SIZE_RANGE, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DigestKey(NativeCULong session, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var digestKey = call.Functions.C_DigestKey;
        if (digestKey is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return digestKey(session, key).ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part message-digesting operation, returning the message digest
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="digest">Receives the digest; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the digest: the module receives a NULL buffer.</param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_DigestFinal(NativeCULong session, Span<byte> digest, bool lengthOnly, out NativeCULong digestLen)
    {
        using ModuleCall call = EnterModule();
        var digestFinal = call.Functions.C_DigestFinal;
        digestLen = (NativeCULong)digest.Length;
        if (digestFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(digest))
        fixed (NativeCULong* lenPtr = &digestLen)
            rv = digestFinal(session, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, digestLen, digest.Length);
    }
}
