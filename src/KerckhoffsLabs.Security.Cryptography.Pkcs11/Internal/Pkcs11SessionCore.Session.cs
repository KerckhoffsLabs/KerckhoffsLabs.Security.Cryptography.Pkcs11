using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    // -----------------------------------------------------------------------
    // InitPin — SecurePin overload (canonical) + obsolete legacy overloads
    // -----------------------------------------------------------------------

    /// <summary>
    /// Initializes the normal user's PIN using a <see cref="SecurePin"/>.
    /// </summary>
    /// <param name="userPin">Pin value</param>
    public void InitPin(SecurePin userPin)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(userPin);


        Log.SessionTrace(_logger, (ulong)_sessionId, "InitPin");

        CKR rv = _pkcs11Library.C_InitPIN(_sessionId, userPin.Pin);
        Pkcs11Exception.ThrowIfError(rv, OpInitPIN);
    }

    /// <summary>
    /// Initializes the normal user's PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. PKCS#11 signals this by calling
    /// <c>C_InitPIN</c> with <c>pPin = NULL_PTR</c>, <c>ulPinLen = 0</c> — this overload passes an
    /// empty span, which the interop layer marshals to a null pointer.
    /// </summary>
    public void InitPin()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "InitPin (protected authentication path)");

        CKR rv = _pkcs11Library.C_InitPIN(_sessionId, default);
        Pkcs11Exception.ThrowIfError(rv, OpInitPIN);
    }

    // -----------------------------------------------------------------------
    // SetPin
    // -----------------------------------------------------------------------

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    public void SetPin(SecurePin oldPin, SecurePin newPin)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);


        Log.SessionTrace(_logger, (ulong)_sessionId, "SetPin");

        CKR rv = _pkcs11Library.C_SetPIN(_sessionId, oldPin.Pin, newPin.Pin);
        Pkcs11Exception.ThrowIfError(rv, OpSetPIN);
    }

    /// <summary>
    /// Modifies the PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Both the old and new PIN are entered on
    /// the device; PKCS#11 signals this by calling <c>C_SetPIN</c> with <c>pOldPin</c> and
    /// <c>pNewPin</c> both <c>NULL_PTR</c> — this overload passes empty spans for both, which the
    /// interop layer marshals to null pointers.
    /// </summary>
    public void SetPin()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetPin (protected authentication path)");

        CKR rv = _pkcs11Library.C_SetPIN(_sessionId, default, default);
        Pkcs11Exception.ThrowIfError(rv, OpSetPIN);
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <returns>Information about a session</returns>
    public SessionInfo GetSessionInfo()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetSessionInfo");

        CK_SESSION_INFO sessionInfo = new();
        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref sessionInfo);
        Pkcs11Exception.ThrowIfError(rv, OpGetSessionInfo);

        return new SessionInfo(_sessionId, sessionInfo);
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as an array of bytes
    /// </summary>
    /// <returns>Operations state of a session</returns>
    public byte[] GetOperationState()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetOperationState");

        return CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_GetOperationState(_sessionId, buffer, lengthOnly, out len),
            OpGetOperationState);
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from an array of bytes obtained with GetOperationState
    /// </summary>
    /// <param name="state">Array of bytes obtained with GetOperationState</param>
    /// <param name="encryptionKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing encryption or decryption operation in the restored session</param>
    /// <param name="authenticationKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing signature, MACing, or verification operation in the restored session</param>
    public void SetOperationState(byte[] state, ObjectHandle encryptionKey, ObjectHandle authenticationKey)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetOperationState");

        ArgumentNullException.ThrowIfNull(state);


        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpSetOperationState);
    }

    // -----------------------------------------------------------------------
    // Login — SecurePin overload (canonical) + obsolete legacy overloads
    // -----------------------------------------------------------------------

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    public void Login(CKU userType, SecurePin pin)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(pin);


        Log.SessionTrace(_logger, (ulong)_sessionId, "Login");

        Log.LoggingIn(_logger, userType, (ulong)_sessionId);

        CKR rv = _pkcs11Library.C_Login(_sessionId, userType, pin.Pin);
        Pkcs11Exception.ThrowIfError(rv, OpLogin);
    }

    /// <summary>
    /// Logs a user into a token via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. PKCS#11 signals this by calling
    /// <c>C_Login</c> with <c>pPin = NULL_PTR</c>, <c>ulPinLen = 0</c> — this overload passes an
    /// empty span, which the interop layer marshals to a null pointer.
    /// </summary>
    /// <param name="userType">Type of user.</param>
    public void Login(CKU userType)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "Login (protected authentication path)");

        Log.LoggingInProtectedPath(_logger, userType, (ulong)_sessionId);

        CKR rv = _pkcs11Library.C_Login(_sessionId, userType, default);
        Pkcs11Exception.ThrowIfError(rv, OpLogin);
    }

    /// <summary>
    /// Logs a user into a token by user type plus a free-form username (PKCS#11 v3.0).
    /// Use this overload for HSMs that support named user accounts beyond SO/User.
    /// </summary>
    /// <param name="userType">Type of user.</param>
    /// <param name="pin">User's PIN. Caller retains ownership; its bytes go to the native
    /// call straight out of the pinned buffer it owns, with no transient copy.</param>
    /// <param name="username">Account username (UTF-8 encoded). Must not be null or empty.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="pin"/> or <paramref name="username"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="username"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from C_LoginUser. <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> indicates the loaded library is v2.40 or otherwise does not export C_LoginUser.</exception>
    public void LoginUser(CKU userType, SecurePin pin, string username)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(username);
        if (username.Length == 0)
            throw new ArgumentException("Username must not be empty.", nameof(username));

        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "LoginUser");

        Log.LoggingInUser(_logger, userType, (ulong)_sessionId);

        byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
        try
        {
            CKR rv = _pkcs11Library.C_LoginUser(_sessionId, userType, pin.Pin, usernameBytes);
            Pkcs11Exception.ThrowIfError(rv, OpLoginUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(usernameBytes);
        }
    }
}
