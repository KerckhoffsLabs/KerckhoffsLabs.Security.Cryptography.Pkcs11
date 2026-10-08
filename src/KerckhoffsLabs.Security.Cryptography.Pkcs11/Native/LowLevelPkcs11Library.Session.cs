using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="pin">Normal user's PIN or null to use protected authentication path (pinpad)</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_SESSION_CLOSED, CKR_SESSION_READ_ONLY, CKR_SESSION_HANDLE_INVALID, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin)
    {
        using ModuleCall call = EnterModule();
        var initPIN = call.Functions.C_InitPIN;
        if (initPIN is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* pinPtr = pin)
            return initPIN(session, pinPtr, (NativeCULong)pin.Length).ToCKR();
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="oldPin">Old PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="newPin">New PIN or null to use protected authentication path (pinpad)</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        using ModuleCall call = EnterModule();
        var setPin = call.Functions.C_SetPIN;
        if (setPin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* oldPinPtr = oldPin)
        fixed (byte* newPinPtr = newPin)
            return setPin(session, oldPinPtr, (NativeCULong)oldPin.Length, newPinPtr, (NativeCULong)newPin.Length).ToCKR();
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="flags">Flags indicating the type of session</param>
    /// <remarks>No notification callback is registered: <c>pApplication</c> and <c>Notify</c> are NULL.</remarks>
    /// <param name="session">Location that receives the handle for the new session</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, ref NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var openSession = call.Functions.C_OpenSession;
        if (openSession is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (NativeCULong* sessionPtr = &session)
            return openSession(slotId, flags, IntPtr.Zero, IntPtr.Zero, sessionPtr).ToCKR();
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_CloseSession(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var closeSession = call.Functions.C_CloseSession;
        if (closeSession is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return closeSession(session).ToCKR();
    }

    /// <summary>
    /// Closes all sessions an application has with a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT</returns>
    public unsafe CKR C_CloseAllSessions(NativeCULong slotId)
    {
        using ModuleCall call = EnterModule();
        var closeAllSessions = call.Functions.C_CloseAllSessions;
        if (closeAllSessions is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return closeAllSessions(slotId).ToCKR();
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="info">Structure that receives the session information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        using ModuleCall call = EnterModule();
        var getSessionInfo = call.Functions.C_GetSessionInfo;
        if (getSessionInfo is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (!Pkcs11Marshal.IsWindows)
        {
            fixed (CK_SESSION_INFO* p = &info)
                return getSessionInfo(session, p).ToCKR();
        }

        CK_SESSION_INFO_Windows packed = default;
        CKR rv = getSessionInfo(session, &packed).ToCKR();
        info = packed.ToUnified();
        return rv;
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as byte array
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">Receives the operation state; ignored when <paramref name="lengthOnly"/>.</param>
    /// <param name="lengthOnly">Asks only for the length of the operation state: the module receives a NULL buffer.</param>
    /// <param name="operationStateLen">Location that receives the length in bytes of the state</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_STATE_UNSAVEABLE, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_GetOperationState(NativeCULong session, Span<byte> operationState, bool lengthOnly, out NativeCULong operationStateLen)
    {
        using ModuleCall call = EnterModule();
        var getOperationState = call.Functions.C_GetOperationState;
        operationStateLen = (NativeCULong)operationState.Length;
        if (getOperationState is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* outPtr = &NonNullPinnable(operationState))
        fixed (NativeCULong* lenPtr = &operationStateLen)
            rv = getOperationState(session, lengthOnly ? null : outPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, operationStateLen, operationState.Length);
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from bytes obtained with C_GetOperationState
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">Saved session state</param>
    /// <param name="encryptionKey">Handle to the key which will be used for an ongoing encryption or decryption operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <param name="authenticationKey">Handle to the key which will be used for an ongoing operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_CHANGED, CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_OK, CKR_SAVED_STATE_INVALID, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey,
        NativeCULong authenticationKey)
    {
        using ModuleCall call = EnterModule();
        var setOperationState = call.Functions.C_SetOperationState;
        if (setOperationState is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* statePtr = operationState)
            return setOperationState(session, statePtr, (NativeCULong)operationState.Length, encryptionKey, authenticationKey).ToCKR();
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="userType">The user type</param>
    /// <param name="pin">User's PIN or null to use protected authentication path (pinpad)</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID</returns>
    public unsafe CKR C_Login(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin)
    {
        using ModuleCall call = EnterModule();
        var login = call.Functions.C_Login;
        if (login is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // An empty PIN reaches the module as NULL: that is how protected authentication path login is asked for.
        fixed (byte* pinPtr = pin)
            return login(session, userType.ToCULong(), pinPtr, (NativeCULong)pin.Length).ToCKR();
    }

    /// <summary>
    /// Logs a user into a token by user type plus a free-form username (PKCS#11 v3.0 §5.6.7).
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="userType">The user type.</param>
    /// <param name="pin">User's PIN bytes, or null for protected-authentication-path tokens.</param>
    /// <param name="username">Username bytes (UTF-8), or null.</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_LoginUser(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        using ModuleCall call = EnterModule();
        var loginUser = call.Functions.C_LoginUser;
        if (loginUser is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* pinPtr = pin)
        fixed (byte* userPtr = username)
            return loginUser(session, userType.ToCULong(), pinPtr, (NativeCULong)pin.Length, userPtr, (NativeCULong)username.Length).ToCKR();
    }

    /// <summary>
    /// Cancels operations in-flight on the session matching the given flags bitmask
    /// (PKCS#11 v3.0 §5.6.8). The session remains open; only the targeted operations
    /// are unwound.
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="flags">Bitmask of operations to cancel (CKF_ENCRYPT, CKF_DECRYPT, CKF_SIGN, etc.).</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        using ModuleCall call = EnterModule();
        var sessionCancel = call.Functions.C_SessionCancel;
        if (sessionCancel is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return sessionCancel(session, flags).ToCKR();
    }

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type (PKCS#11 v3.2 §5.6.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        using ModuleCall call = EnterModule();
        var getSessionValidationFlags = call.Functions.C_GetSessionValidationFlags;
        if (getSessionValidationFlags is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (NativeCULong* flagsPtr = &flags)
            return getSessionValidationFlags(session, type, flagsPtr).ToCKR();
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_Logout(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var logout = call.Functions.C_Logout;
        if (logout is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return logout(session).ToCKR();
    }

    /// <summary>
    /// Calls <c>C_CloseSession</c> from <paramref name="table"/> without entering the module: the session's
    /// release path already holds its own use of the module.
    /// </summary>
    /// <param name="table">The module's function table.</param>
    /// <param name="session">The session's handle.</param>
    internal static unsafe CKR CloseSession(Delegates table, NativeCULong session)
    {
        var closeSession = table._fp.C_CloseSession;
        return closeSession is null ? CKR.CKR_FUNCTION_NOT_SUPPORTED : closeSession(session).ToCKR();
    }
}
