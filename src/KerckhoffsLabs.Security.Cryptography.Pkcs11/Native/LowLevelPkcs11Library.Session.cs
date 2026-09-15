// <auto-split-from LowLevelPkcs11Library.cs>
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
    public CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_InitPIN(session, pin);
        return rv.ToCKR();
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="oldPin">Old PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="newPin">New PIN or null to use protected authentication path (pinpad)</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SetPIN(session, oldPin, newPin);
        return rv.ToCKR();
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="flags">Flags indicating the type of session</param>
    /// <param name="application">An application defined pointer to be passed to the notification callback</param>
    /// <param name="notify">The address of the notification callback function</param>
    /// <param name="session">Location that receives the handle for the new session</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_OpenSession(slotId, flags, application, notify, ref session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_CloseSession(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_CloseSession(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Closes all sessions an application has with a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT</returns>
    public CKR C_CloseAllSessions(NativeCULong slotId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_CloseAllSessions(slotId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="info">Structure that receives the session information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetSessionInfo(session, ref info).ToCKR();
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as byte array
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">
    /// If set to null then the length of state is returned in "operationStateLen" parameter, without actually returning a state.
    /// If not set to null then "operationStateLen" parameter must contain the lenght of operationState array and state is returned in "operationState" parameter.
    /// </param>
    /// <param name="operationStateLen">Location that receives the length in bytes of the state</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_STATE_UNSAVEABLE, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetOperationState(NativeCULong session, Span<byte> operationState, out NativeCULong operationStateLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetOperationState(session, operationState, out operationStateLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from bytes obtained with C_GetOperationState
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">Saved session state</param>
    /// <param name="encryptionKey">Handle to the key which will be used for an ongoing encryption or decryption operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <param name="authenticationKey">Handle to the key which will be used for an ongoing operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_CHANGED, CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_OK, CKR_SAVED_STATE_INVALID, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey,
        NativeCULong authenticationKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SetOperationState(session, operationState, encryptionKey, authenticationKey);
        return rv.ToCKR();
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="userType">The user type</param>
    /// <param name="pin">User's PIN or null to use protected authentication path (pinpad)</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID</returns>
    public CKR C_Login(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Login(session, userType.ToCULong(), pin);
        return rv.ToCKR();
    }

    /// <summary>
    /// Logs a user into a token by user type plus a free-form username (PKCS#11 v3.0 §5.6.7).
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="userType">The user type.</param>
    /// <param name="pin">User's PIN bytes, or null for protected-authentication-path tokens.</param>
    /// <param name="username">Username bytes (UTF-8), or null.</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_LoginUser(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_LoginUser)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_LoginUser(session, userType.ToCULong(), pin, username);
        return rv.ToCKR();
    }

    /// <summary>
    /// Cancels operations in-flight on the session matching the given flags bitmask
    /// (PKCS#11 v3.0 §5.6.8). The session remains open; only the targeted operations
    /// are unwound.
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="flags">Bitmask of operations to cancel (CKF_ENCRYPT, CKF_DECRYPT, CKF_SIGN, etc.).</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.IsC_SessionCancelSupported)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SessionCancel(session, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type (PKCS#11 v3.2 §5.6.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_GetSessionValidationFlags)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_GetSessionValidationFlags(session, type, ref flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_Logout(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Logout(session);
        return rv.ToCKR();
    }
}
