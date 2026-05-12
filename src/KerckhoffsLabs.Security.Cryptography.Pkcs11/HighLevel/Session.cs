using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Class representing a logical connection between an application and a token
/// </summary>
public partial class Session
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    protected bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private Pkcs11InteropLogger _logger = Pkcs11InteropLoggerFactory.GetLogger(typeof(Session));

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    protected LowLevelPkcs11Library _pkcs11Library = null;

    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    protected NativeCULong _sessionId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    public ulong SessionId
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return (ulong)_sessionId;
        }
    }

    /// <summary>
    /// Flag indicating whether session should be closed when object is disposed
    /// </summary>
    protected bool _closeWhenDisposed = true;

    /// <summary>
    /// Flag indicating whether session should be closed when object is disposed
    /// </summary>
    public bool CloseWhenDisposed
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _closeWhenDisposed;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _logger.Debug("Session({0})::CloseWhenDisposed", _sessionId);

            _closeWhenDisposed = value;
        }
    }

    /// <summary>Backing field for <see cref="AllowInsecure"/>.</summary>
    protected bool _allowInsecure = false;

    /// <summary>
    /// When <c>true</c>, this session does not reject operations that use mechanisms flagged as
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, etc.). Default is <c>false</c>.
    /// Set explicitly per session; never set this globally.
    /// </summary>
    public bool AllowInsecure
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _allowInsecure;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _allowInsecure = value;
        }
    }

    /// <summary>
    /// Initializes new instance of Session class
    /// </summary>
    /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    protected internal Session(LowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        _logger.Debug("Session({0})::ctor", sessionId);

        if (pkcs11Library == null)
            throw new ArgumentNullException("pkcs11Library");

        if (sessionId == (ulong)CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", "sessionId");

        _pkcs11Library = pkcs11Library;
        _sessionId = (NativeCULong)(sessionId);
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    public void CloseSession()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CloseSession", _sessionId);

        _logger.Info("Closing session {0}", _sessionId);

        CKR rv = _pkcs11Library.C_CloseSession(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CloseSession", rv);

        _sessionId = CK.CK_INVALID_HANDLE;
    }

    // -----------------------------------------------------------------------
    // InitPin — core helper + SecurePin overload + obsolete legacy overloads
    // -----------------------------------------------------------------------

    private void InitPinCore(ReadOnlySpan<byte> userPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::InitPin", _sessionId);

        byte[] tmp = userPin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_InitPIN(_sessionId, tmp, (NativeCULong)tmp.Length);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitPIN", rv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>
    /// Initializes the normal user's PIN using a <see cref="SecurePin"/>.
    /// </summary>
    /// <param name="userPin">Pin value</param>
    public void InitPin(SecurePin userPin)
    {
        ArgumentNullException.ThrowIfNull(userPin);
        InitPinCore(userPin.Pin);
    }

    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="userPin">Pin value</param>
    [Obsolete("Use the SecurePin overload — string PINs cannot be zeroed (strings are immutable " +
              "and may be interned). string is allowed for backward compatibility.",
              error: false)]
    public void InitPin(string userPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::InitPin1", _sessionId);

        if (userPin == null)
        {
            // Null-pin path preserved for backward compatibility.
            CKR rv0 = _pkcs11Library.C_InitPIN(_sessionId, null, (NativeCULong)0);
            if (rv0 != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitPIN", rv0);
            return;
        }

        int byteCount = Encoding.UTF8.GetByteCount(userPin);
        using var tmp = new SecureBuffer(byteCount);
        Encoding.UTF8.GetBytes(userPin, tmp.Span);
        InitPinCore(tmp.Span);
    }

    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="userPin">Pin value</param>
    [Obsolete("Use the SecurePin overload — byte[] PIN buffers cannot be reliably zeroed. " +
              "byte[] is allowed for backward compatibility but does not pin or zero the PIN.",
              error: false)]
    public void InitPin(byte[] userPin)
    {
        ArgumentNullException.ThrowIfNull(userPin);
        InitPinCore(userPin);
    }

    // -----------------------------------------------------------------------
    // SetPin — core helper + SecurePin overload + obsolete legacy overloads
    // -----------------------------------------------------------------------

    private void SetPinCore(ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetPin", _sessionId);

        byte[] oldTmp = oldPin.ToArray();
        byte[] newTmp = newPin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_SetPIN(
                _sessionId,
                oldTmp, (NativeCULong)oldTmp.Length,
                newTmp, (NativeCULong)newTmp.Length);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_SetPIN", rv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldTmp);
            CryptographicOperations.ZeroMemory(newTmp);
        }
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    public void SetPin(SecurePin oldPin, SecurePin newPin)
    {
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        SetPinCore(oldPin.Pin, newPin.Pin);
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    [Obsolete("Use the SecurePin overload — string PINs cannot be zeroed (strings are immutable " +
              "and may be interned). string is allowed for backward compatibility.",
              error: false)]
    public void SetPin(string oldPin, string newPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetPin1", _sessionId);

        ReadOnlySpan<byte> oldSpan = ReadOnlySpan<byte>.Empty;
        ReadOnlySpan<byte> newSpan = ReadOnlySpan<byte>.Empty;

        SecureBuffer? oldBuf = null;
        SecureBuffer? newBuf = null;
        try
        {
            if (oldPin != null)
            {
                int oldCount = Encoding.UTF8.GetByteCount(oldPin);
                oldBuf = new SecureBuffer(oldCount);
                Encoding.UTF8.GetBytes(oldPin, oldBuf.Span);
                oldSpan = oldBuf.Span;
            }

            if (newPin != null)
            {
                int newCount = Encoding.UTF8.GetByteCount(newPin);
                newBuf = new SecureBuffer(newCount);
                Encoding.UTF8.GetBytes(newPin, newBuf.Span);
                newSpan = newBuf.Span;
            }

            SetPinCore(oldSpan, newSpan);
        }
        finally
        {
            oldBuf?.Dispose();
            newBuf?.Dispose();
        }
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    [Obsolete("Use the SecurePin overload — byte[] PIN buffers cannot be reliably zeroed. " +
              "byte[] is allowed for backward compatibility but does not pin or zero the PIN.",
              error: false)]
    public void SetPin(byte[] oldPin, byte[] newPin)
    {
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        SetPinCore(oldPin, newPin);
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <returns>Information about a session</returns>
    public SessionInfo GetSessionInfo()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetSessionInfo", _sessionId);

        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref sessionInfo);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetSessionInfo", rv);

        return new SessionInfo(_sessionId, sessionInfo);
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as an array of bytes
    /// </summary>
    /// <returns>Operations state of a session</returns>
    public byte[] GetOperationState()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetOperationState", _sessionId);

        NativeCULong operationStateLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetOperationState(_sessionId, null, ref operationStateLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetOperationState", rv);

        byte[] operationState = new byte[(int)operationStateLen];
        rv = _pkcs11Library.C_GetOperationState(_sessionId, operationState, ref operationStateLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetOperationState", rv);

        return operationState;
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from an array of bytes obtained with GetOperationState
    /// </summary>
    /// <param name="state">Array of bytes obtained with GetOperationState</param>
    /// <param name="encryptionKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing encryption or decryption operation in the restored session</param>
    /// <param name="authenticationKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing signature, MACing, or verification operation in the restored session</param>
    public void SetOperationState(byte[] state, ObjectHandle encryptionKey, ObjectHandle authenticationKey)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetOperationState", _sessionId);

        if (state == null)
            throw new ArgumentNullException("state");

        if (encryptionKey == null)
            throw new ArgumentNullException("encryptionKey");

        if (authenticationKey == null)
            throw new ArgumentNullException("authenticationKey");

        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(state.Length), (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SetOperationState", rv);
    }

    // -----------------------------------------------------------------------
    // Login — core helper + SecurePin overload + obsolete legacy overloads
    // -----------------------------------------------------------------------

    private void LoginCore(CKU userType, ReadOnlySpan<byte> pin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Login", _sessionId);

        if (_logger.IsEnabled(Pkcs11InteropLogLevel.Info))
            _logger.Info("Logging as {0} into session {1}", Pkcs11InteropLogUtils.ToString(userType), _sessionId);

        byte[] tmp = pin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_Login(_sessionId, userType, tmp, (NativeCULong)tmp.Length);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    public void Login(CKU userType, SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        LoginCore(userType, pin.Pin);
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    [Obsolete("Use the SecurePin overload — string PINs cannot be zeroed (strings are immutable " +
              "and may be interned). string is allowed for backward compatibility.",
              error: false)]
    public void Login(CKU userType, string pin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Login1", _sessionId);

        if (pin == null)
        {
            // Null-pin path preserved for backward compatibility.
            if (_logger.IsEnabled(Pkcs11InteropLogLevel.Info))
                _logger.Info("Logging as {0} into session {1}", Pkcs11InteropLogUtils.ToString(userType), _sessionId);
            CKR rv0 = _pkcs11Library.C_Login(_sessionId, userType, null, (NativeCULong)0);
            if (rv0 != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv0);
            return;
        }

        int byteCount = Encoding.UTF8.GetByteCount(pin);
        using var tmp = new SecureBuffer(byteCount);
        Encoding.UTF8.GetBytes(pin, tmp.Span);
        LoginCore(userType, tmp.Span);
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    [Obsolete("Use the SecurePin overload — byte[] PIN buffers cannot be reliably zeroed. " +
              "byte[] is allowed for backward compatibility but does not pin or zero the PIN.",
              error: false)]
    public void Login(CKU userType, byte[] pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        LoginCore(userType, pin);
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    public void Logout()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Logout", _sessionId);

        _logger.Info("Logging out of session {0}", _sessionId);

        CKR rv = _pkcs11Library.C_Logout(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Logout", rv);
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void GetFunctionStatus()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetFunctionStatus", _sessionId);

        CKR rv = _pkcs11Library.C_GetFunctionStatus(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetFunctionStatus", rv);
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void CancelFunction()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CancelFunction", _sessionId);

        CKR rv = _pkcs11Library.C_CancelFunction(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CancelFunction", rv);
    }

    /// <summary>
    /// Checks the given mechanism against the insecure-mechanism set and throws
    /// <see cref="InsecureOperationException"/> if it is insecure and <see cref="AllowInsecure"/>
    /// is false.
    /// </summary>
    private void GuardMechanism(CKM mechanism)
    {
        if (AllowInsecure) return;

        switch (mechanism)
        {
            case CKM.CKM_RSA_PKCS:
                throw new InsecureOperationException(mechanism,
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_MD5_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                throw new InsecureOperationException(mechanism,
                    "MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too); use CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 instead.");
            case CKM.CKM_MD5:
            case CKM.CKM_SHA_1:
                throw new InsecureOperationException(mechanism,
                    "MD5 and SHA-1 are broken hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_DES_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CBC_PAD) instead.");
            case CKM.CKM_DES_MAC:
            case CKM.CKM_DES_MAC_GENERAL:
            case CKM.CKM_DES3_MAC:
            case CKM.CKM_DES3_MAC_GENERAL:
                throw new InsecureOperationException(mechanism,
                    "DES/3DES MAC is weak; use CKM_AES_CMAC or CKM_SHA256_HMAC instead.");
            case CKM.CKM_DES_KEY_GEN:
            case CKM.CKM_DES2_KEY_GEN:
            case CKM.CKM_DES3_KEY_GEN:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES key generation produces deprecated keys; use CKM_AES_KEY_GEN instead.");
            case CKM.CKM_DES3_ECB_ENCRYPT_DATA:
            case CKM.CKM_DES3_CBC_ENCRYPT_DATA:
                throw new InsecureOperationException(mechanism,
                    "DES3 key-derive mechanisms are weak; use CKM_SP800_108-family KDFs or CKM_AES_CBC_ENCRYPT_DATA on a strong base key instead.");
            case CKM.CKM_AES_ECB:
                throw new InsecureOperationException(mechanism,
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CBC_PAD instead.");
            default:
                return;
        }
    }

    #region IDisposable

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        _logger.Debug("Session({0})::Dispose1", _sessionId);

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    protected virtual void Dispose(bool disposing)
    {
        _logger.Debug("Session({0})::Dispose2", _sessionId);

        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
                if (_sessionId != CK.CK_INVALID_HANDLE && _closeWhenDisposed == true)
                    CloseSession();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Session()
    {
        Dispose(false);
    }

    #endregion
}