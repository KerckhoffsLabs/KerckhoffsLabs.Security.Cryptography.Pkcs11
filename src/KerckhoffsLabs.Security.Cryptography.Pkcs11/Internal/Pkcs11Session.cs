using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Class representing a logical connection between an application and a token
/// </summary>
internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Session>();

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private LowLevelPkcs11Library _pkcs11Library = null;

    /// <summary>
    /// SafeHandle wrapping the PKCS#11 session handle. Owns the session lifetime and
    /// calls <c>C_CloseSession</c> on release via its <c>ReleaseHandle</c> override.
    /// Private because <see cref="Pkcs11SessionHandle"/> is internal; partials and subclasses
    /// access the session ID through the <see cref="_sessionId"/> shim property.
    /// </summary>
    private Pkcs11SessionHandle _sessionHandle = null!;

    /// <summary>
    /// Compatibility shim — returns the underlying session ID, or <see cref="CK.CK_INVALID_HANDLE"/>
    /// if the session is not yet open or has been closed. Read-only; assignments go through
    /// <see cref="_sessionHandle"/>.
    /// </summary>
    private NativeCULong _sessionId
    {
        get => _sessionHandle is null ? CK.CK_INVALID_HANDLE : _sessionHandle.SessionId;
    }

    /// <summary>
    /// Lock object guarding concurrent native-call access to this <see cref="Pkcs11Session"/>.
    /// PKCS#11 sessions are not safe for concurrent use; this lock detects cross-thread
    /// attempts and throws <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="Monitor"/> (via <see cref="Monitor.TryEnter(object)"/>) is reentrant on the
    /// same thread, which is required because secure helpers like <c>GenerateAesKey</c>
    /// internally call the public <c>GenerateKey</c>. Re-entry from the same thread succeeds;
    /// a different thread calling while the lock is held fails immediately and
    /// <see cref="AcquireExclusive"/> throws.
    /// </remarks>
    private readonly object _busyLock = new();

    /// <summary>Disposable token returned by <see cref="AcquireExclusive"/>. Releases the busy lock on dispose.</summary>
    /// <remarks>
    /// Implemented as <c>internal sealed class</c> (not <c>ref struct</c>) so the test suite can
    /// invoke <see cref="AcquireExclusive"/> via <c>[InternalsVisibleTo]</c> and hold the lease
    /// across a thread boundary. The one extra heap allocation per public method call is
    /// negligible against the cost of crossing the P/Invoke boundary that follows.
    /// </remarks>
    internal sealed class ExclusiveLease : IDisposable
    {
        private readonly object _lock;
        private bool _released;

        internal ExclusiveLease(object lockObj)
        {
            _lock = lockObj;
            _released = false;
        }

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            Monitor.Exit(_lock);
        }
    }

    /// <summary>
    /// Acquires exclusive access to this session for the duration of the returned
    /// <see cref="ExclusiveLease"/>. Throws <see cref="InvalidOperationException"/> if another
    /// thread is already inside an exclusive section.
    /// </summary>
    /// <remarks>
    /// Usage: <c>using var _ = AcquireExclusive(); ...</c>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown if a different thread currently holds the lock. The message identifies the caller
    /// via <see cref="System.Runtime.CompilerServices.CallerMemberNameAttribute"/>.
    /// </exception>
    internal ExclusiveLease AcquireExclusive([System.Runtime.CompilerServices.CallerMemberName] string? caller = null)
    {
        if (!Monitor.TryEnter(_busyLock))
        {
            throw new InvalidOperationException(
                $"Concurrent access to a PKCS#11 Session is not supported. " +
                $"Method '{caller ?? "<unknown>"}' was invoked while another operation is in progress " +
                $"on a different thread. Use a separate Session per thread.");
        }
        return new ExclusiveLease(_busyLock);
    }

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
    private bool _closeWhenDisposed = true;

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

            _logger.LogDebug("Session({SessionId})::CloseWhenDisposed", _sessionId);

            _closeWhenDisposed = value;
        }
    }

    /// <summary>Backing field for <see cref="AllowInsecure"/>.</summary>
    private bool _allowInsecure = false;

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
    internal Pkcs11Session(LowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        _logger.LogDebug("Session({SessionId})::ctor", sessionId);

        ArgumentNullException.ThrowIfNull(pkcs11Library);

        if (sessionId == (ulong)CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", "sessionId");

        _pkcs11Library = pkcs11Library;
        _sessionHandle = new Pkcs11SessionHandle(_pkcs11Library, (NativeCULong)sessionId);
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    public void CloseSession()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (_sessionHandle is null || _sessionHandle.IsInvalid)
            return;

        _logger.LogDebug("Session({SessionId})::CloseSession", _sessionId);

        _logger.LogInformation("Closing session {SessionId}", _sessionId);

        // SafeHandle.Dispose() calls ReleaseHandle, which invokes C_CloseSession on the library.
        _sessionHandle.Dispose();
        _sessionHandle = null!;
    }

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

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::InitPin", _sessionId);

        byte[] tmp = userPin.Pin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_InitPIN(_sessionId, tmp, (NativeCULong)tmp.Length);
            Pkcs11Exception.ThrowIfError(rv, "C_InitPIN");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
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

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::SetPin", _sessionId);

        byte[] oldTmp = oldPin.Pin.ToArray();
        byte[] newTmp = newPin.Pin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_SetPIN(
                _sessionId,
                oldTmp, (NativeCULong)oldTmp.Length,
                newTmp, (NativeCULong)newTmp.Length);
            Pkcs11Exception.ThrowIfError(rv, "C_SetPIN");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldTmp);
            CryptographicOperations.ZeroMemory(newTmp);
        }
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <returns>Information about a session</returns>
    public SessionInfo GetSessionInfo()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::GetSessionInfo", _sessionId);

        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref sessionInfo);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSessionInfo");

        return new SessionInfo(_sessionId, sessionInfo);
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as an array of bytes
    /// </summary>
    /// <returns>Operations state of a session</returns>
    public byte[] GetOperationState()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::GetOperationState", _sessionId);

        NativeCULong operationStateLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetOperationState(_sessionId, null, ref operationStateLen);
        Pkcs11Exception.ThrowIfError(rv, "C_GetOperationState");

        byte[] operationState = new byte[(int)operationStateLen];
        rv = _pkcs11Library.C_GetOperationState(_sessionId, operationState, ref operationStateLen);
        Pkcs11Exception.ThrowIfError(rv, "C_GetOperationState");

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::SetOperationState", _sessionId);

        ArgumentNullException.ThrowIfNull(state);


        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(state.Length), (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_SetOperationState");
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

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::Login", _sessionId);

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Logging as {UserType} into session {SessionId}", Pkcs11LogUtils.ToString(userType), _sessionId);

        byte[] tmp = pin.Pin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_Login(_sessionId, userType, tmp, (NativeCULong)tmp.Length);
            Pkcs11Exception.ThrowIfError(rv, "C_Login");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    public void Logout()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::Logout", _sessionId);

        _logger.LogInformation("Logging out of session {SessionId}", _sessionId);

        CKR rv = _pkcs11Library.C_Logout(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, "C_Logout");
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void GetFunctionStatus()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::GetFunctionStatus", _sessionId);

        CKR rv = _pkcs11Library.C_GetFunctionStatus(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, "C_GetFunctionStatus");
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void CancelFunction()
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.LogDebug("Session({SessionId})::CancelFunction", _sessionId);

        CKR rv = _pkcs11Library.C_CancelFunction(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, "C_CancelFunction");
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
        _logger.LogDebug("Session({SessionId})::Dispose1", _sessionId);

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    private void Dispose(bool disposing)
    {
        _logger.LogDebug("Session({SessionId})::Dispose2", _sessionId);

        if (!_disposed)
        {
            if (disposing)
            {
                // Managed cleanup — release the session handle (SafeHandle releases via C_CloseSession).
                // Honour _closeWhenDisposed: only close if the caller wants automatic close on dispose.
                if (_closeWhenDisposed)
                {
                    _sessionHandle?.Dispose();
                    _sessionHandle = null!;
                }
            }

            // No unmanaged resources owned by Session directly — Pkcs11SessionHandle owns the
            // session ID, and Pkcs11ModuleHandle (held transitively via _pkcs11Library) owns the
            // library module. Both are SafeHandles and run their own critical finalizers.
            _disposed = true;
        }
    }

    // NOTE: ~Session() finalizer intentionally removed.
    // Pkcs11SessionHandle is a SafeHandle (CriticalFinalizerObject) and runs its own critical
    // finalizer after regular finalizers, which is exactly the correct order for native-handle
    // cleanup.  The Pkcs11SessionHandle also holds a strong reference to LowLevelPkcs11Library,
    // keeping the library's Pkcs11ModuleHandle reachable for as long as any session handle lives.

    #endregion
}