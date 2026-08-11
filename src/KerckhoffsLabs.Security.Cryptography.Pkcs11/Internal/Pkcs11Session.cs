using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Class representing a logical connection between an application and a token
/// </summary>
internal sealed class Pkcs11Session : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed. Written under <see cref="_busyLock"/>,
    /// but read outside it by the property guards, so it is <c>volatile</c>: a disposal on one
    /// thread has to be visible to the next caller on another without the reader taking the lock.
    /// </summary>
    private volatile bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Session>();

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private readonly ILowLevelPkcs11Library _pkcs11Library;

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
    private NativeCULong _sessionId => _sessionHandle is null ? CK.CK_INVALID_HANDLE : _sessionHandle.SessionId;

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
    /// <para>
    /// <see cref="Dispose(bool)"/> is the one exception: it waits for the lock instead of throwing,
    /// because it cannot report contention by throwing and it must not close the session under an
    /// in-flight native call. See the comment there.
    /// </para>
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

            Log.SessionTrace(_logger, (ulong)_sessionId, "CloseWhenDisposed");

            _closeWhenDisposed = value;
        }
    }

    /// <summary>Backing field for <see cref="AllowInsecure"/>.</summary>
    private bool _allowInsecure = false;

    /// <summary>
    /// When <c>true</c>, this session does not reject operations that use mechanisms flagged as
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, etc.). Default is <c>false</c>.
    /// Set explicitly per session; never set this globally. Prefer <see cref="AllowInsecureScope"/>
    /// for a single operation rather than leaving the flag latched on for the session lifetime.
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

            // Warn on every transition into the insecure state so the relaxation is auditable.
            if (value && !_allowInsecure)
                _logger.LogWarning(
                    "Session({SessionId})::AllowInsecure enabled — insecure-by-default mechanisms " +
                    "(RSA PKCS#1 v1.5, DES/3DES, AES-ECB, MD5/SHA-1) are no longer gated on this session.",
                    _sessionId);

            _allowInsecure = value;
        }
    }

    /// <summary>
    /// Enables <see cref="AllowInsecure"/> for the duration of the returned lease and restores the
    /// previous value when the lease is disposed. Use this to opt into an insecure mechanism for a
    /// single operation rather than latching the flag on for the whole session:
    /// <code>using (session.AllowInsecureScope()) { /* one insecure op */ }</code>
    /// Nested scopes restore in LIFO order. Logs a warning on entry (via the setter).
    /// </summary>
    public IDisposable AllowInsecureScope()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        bool previous = _allowInsecure;
        AllowInsecure = true; // routes through the setter so the transition is logged
        return new AllowInsecureLease(this, previous);
    }

    /// <summary>Disposable returned by <see cref="AllowInsecureScope"/>. Restores the prior flag value on dispose.</summary>
    private sealed class AllowInsecureLease(Pkcs11Session session, bool previous) : IDisposable
    {
        private bool _released;

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            // Restore directly (not via the setter) so unwinding never re-logs a "now insecure" warning.
            if (!session._disposed)
                session._allowInsecure = previous;
        }
    }

    /// <summary>
    /// Lazy-cached set of mechanism types supported by the token in this session's slot.
    /// Populated on first access via C_GetSessionInfo + C_GetMechanismList. Both the population
    /// and the reads run under <see cref="_busyLock"/>, which is what publishes the set safely.
    /// </summary>
    private HashSet<CKM>? _supportedMechanisms;

    /// <summary>
    /// Returns true if the token in this session's slot supports the given mechanism.
    /// Result is cached after the first call.
    /// </summary>
    /// <remarks>
    /// Takes the busy lock for the whole body, like every other native-touching method: the probe
    /// issues C_GetSessionInfo and C_GetMechanismList, which must not overlap another thread's
    /// in-flight call on this session. The lock spans the cached read as well, because reading the
    /// cache reference outside it is the unsafe-publication half of the same race — one thread can
    /// otherwise observe the reference before the set it points at is fully constructed.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown if another thread is currently inside an operation on this session.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    internal bool SupportsMechanism(CKM mechanism)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_supportedMechanisms is null)
        {
            CK_SESSION_INFO info = new();
            CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref info);
            if (rv != CKR.CKR_OK) return false;

            NativeCULong count = new(0);
            rv = _pkcs11Library.C_GetMechanismList(info.SlotId, null, ref count);
            if (rv != CKR.CKR_OK || count.Value == 0)
            {
                _supportedMechanisms = [];
                return false;
            }

            CKM[] list = new CKM[(int)count.Value];
            rv = _pkcs11Library.C_GetMechanismList(info.SlotId, list, ref count);
            _supportedMechanisms = rv == CKR.CKR_OK ? [.. list] : [];
        }
        return _supportedMechanisms.Contains(mechanism);
    }

    /// <summary>
    /// Wraps an already-open PKCS#11 session handle.
    /// </summary>
    /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    internal Pkcs11Session(ILowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        Log.SessionTrace(_logger, sessionId, "ctor");

        ArgumentNullException.ThrowIfNull(pkcs11Library);

        if (sessionId == (ulong)CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", nameof(sessionId));

        _pkcs11Library = pkcs11Library;
        _sessionHandle = new Pkcs11SessionHandle(_pkcs11Library, (NativeCULong)sessionId);
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    public void CloseSession()
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_sessionHandle is null || _sessionHandle.IsInvalid)
            return;

        Log.SessionTrace(_logger, (ulong)_sessionId, "CloseSession");

        Log.ClosingSession(_logger, (ulong)_sessionId);

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

        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "InitPin");

        byte[] tmp = userPin.ToPinnedArray();
        try
        {
            CKR rv = _pkcs11Library.C_InitPIN(_sessionId, tmp, (NativeCULong)tmp.Length);
            Pkcs11Exception.ThrowIfError(rv, OpInitPIN);
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

        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetPin");

        byte[] oldTmp = oldPin.ToPinnedArray();
        byte[] newTmp = newPin.ToPinnedArray();
        try
        {
            CKR rv = _pkcs11Library.C_SetPIN(
                _sessionId,
                oldTmp, (NativeCULong)oldTmp.Length,
                newTmp, (NativeCULong)newTmp.Length);
            Pkcs11Exception.ThrowIfError(rv, OpSetPIN);
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
        ObjectDisposedException.ThrowIf(_disposed, this);

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
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetOperationState");

        return CallWithLengthProbe(
            (byte[]? buffer, ref NativeCULong len) => _pkcs11Library.C_GetOperationState(_sessionId, buffer, ref len),
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetOperationState");

        ArgumentNullException.ThrowIfNull(state);


        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(state.Length), (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
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

        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Login");

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Logging as {UserType} into session {SessionId}", Pkcs11LogUtils.ToString(userType), _sessionId);

        byte[] tmp = pin.ToPinnedArray();
        try
        {
            CKR rv = _pkcs11Library.C_Login(_sessionId, userType, tmp, (NativeCULong)tmp.Length);
            Pkcs11Exception.ThrowIfError(rv, OpLogin);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>
    /// Logs a user into a token by user type plus a free-form username (PKCS#11 v3.0).
    /// Use this overload for HSMs that support named user accounts beyond SO/User.
    /// </summary>
    /// <param name="userType">Type of user.</param>
    /// <param name="pin">User's PIN. Caller retains ownership; the PIN bytes are copied
    /// into a transient buffer and zeroed before the method returns.</param>
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

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation(
                "Logging in as {UserType} (username supplied) on session {SessionId}",
                Pkcs11LogUtils.ToString(userType), _sessionId);

        byte[] pinTmp = pin.ToPinnedArray();
        byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
        try
        {
            CKR rv = _pkcs11Library.C_LoginUser(
                _sessionId, userType,
                pinTmp, (NativeCULong)pinTmp.Length,
                usernameBytes, (NativeCULong)usernameBytes.Length);
            Pkcs11Exception.ThrowIfError(rv, OpLoginUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinTmp);
            CryptographicOperations.ZeroMemory(usernameBytes);
        }
    }

    /// <summary>
    /// Cancels in-flight cryptographic operations on this session, identified by the
    /// flags bitmask (e.g. CKF_ENCRYPT | CKF_DECRYPT). The session itself remains
    /// open; only the targeted operations are unwound (PKCS#11 v3.0 §5.6.8).
    /// </summary>
    /// <param name="flags">Bitmask of operations to cancel.</param>
    /// <exception cref="Pkcs11Exception">Propagated from C_SessionCancel. <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> indicates the loaded library is v2.40 or otherwise does not export C_SessionCancel.</exception>
    public void CancelOperations(ulong flags)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionCancelOperations(_logger, (ulong)_sessionId, flags);

        CKR rv = _pkcs11Library.C_SessionCancel(_sessionId, (NativeCULong)flags);
        Pkcs11Exception.ThrowIfError(rv, OpSessionCancel);
    }

    /// <summary>
    /// Best-effort cancel of one or more in-flight operations. Intended for the unwind path
    /// of multi-part stream methods so a mid-operation exception cannot leave the session
    /// wedged in active-operation state. Tries <c>C_SessionCancel</c> (PKCS#11 v3.0+); on
    /// v2.40 modules that return <c>CKR_FUNCTION_NOT_SUPPORTED</c> the operation may stay
    /// active, but the caller's exception is the appropriate signal to the consumer.
    /// Errors are logged and swallowed so the original exception is never masked on unwind.
    /// </summary>
    private void TryCancelOperation(NativeCULong flags, string operationName)
    {
        try
        {
            CKR rv = _pkcs11Library.C_SessionCancel(_sessionId, flags);
            if (rv is not CKR.CKR_OK and not CKR.CKR_FUNCTION_NOT_SUPPORTED)
            {
                _logger.LogWarning(
                    "Session({SessionId})::{Operation}: C_SessionCancel returned {Rv} during cleanup",
                    _sessionId, operationName, rv);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Session({SessionId})::{Operation}: C_SessionCancel threw during cleanup",
                _sessionId, operationName);
        }
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    public void Logout()
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Logout");

        Log.LoggingOutSession(_logger, (ulong)_sessionId);

        CKR rv = _pkcs11Library.C_Logout(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpLogout);
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void GetFunctionStatus()
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetFunctionStatus");

        CKR rv = _pkcs11Library.C_GetFunctionStatus(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpGetFunctionStatus);
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void CancelFunction()
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "CancelFunction");

        CKR rv = _pkcs11Library.C_CancelFunction(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpCancelFunction);
    }

    /// <summary>
    /// Checks the given mechanism against the insecure-mechanism set and throws
    /// <see cref="InsecureOperationException"/> if it is insecure and <see cref="AllowInsecure"/>
    /// is false.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the single, mechanism-level secure-defaults gate; it fires identically for sign,
    /// verify, encrypt, decrypt, derive, digest, and key generation (it has no notion of operation
    /// direction).
    /// </para>
    /// <para><b>RSA PKCS#1 v1.5 policy.</b> The split is deliberate and along two axes —
    /// broken hash vs. dangerous padding-use — not "v1.5 vs. PSS":
    /// <list type="bullet">
    /// <item>Gated: any <em>broken hash</em> in an RSA signature mechanism
    /// (<c>CKM_MD2/MD5/SHA1/RIPEMD128/RIPEMD160_RSA_PKCS</c>, <c>CKM_SHA1_RSA_PKCS_PSS</c>).</item>
    /// <item>Gated: PKCS#1 v1.5 <em>encryption</em> / raw RSA (<c>CKM_RSA_PKCS</c>, <c>CKM_RSA_X_509</c>)
    /// — this is where Bleichenbacher/ROBOT padding-oracle attacks live.</item>
    /// <item><b>Allowed:</b> strong-hash (SHA-2/SHA-3) v1.5 <em>signatures</em>
    /// (<c>CKM_SHA256_RSA_PKCS</c> etc.). RSASSA-PKCS1-v1_5 with a strong hash is FIPS 186-5-approved
    /// and mandated by JWT RS256, TLS 1.2 CertificateVerify, X.509, and code signing. Because this
    /// guard is direction-agnostic, gating it would also block <em>verifying</em> third-party
    /// signatures — so gating a secure, ubiquitous scheme would both break interop and dilute the
    /// meaning of <see cref="AllowInsecure"/>. PSS is preferred for new code but not required.</item>
    /// </list>
    /// Mirrored in <c>RSAPkcs11.SignMechanismFor</c> and the README "Security model" section.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Rejects one descriptor driving both halves of a dual-mechanism operation when the token writes
    /// into it.
    /// </summary>
    /// <remarks>
    /// Sharing a descriptor is legal and safe in general: each mechanism marshals into its own block.
    /// The exception is a descriptor with output fields used for both halves of the same call — both
    /// absorb into the same managed buffer, so whichever runs last wins and the other result is lost
    /// with no error anywhere. Rejecting it up front costs nothing and the alternative is a wrong
    /// answer.
    /// </remarks>
    private static void ThrowIfOneDescriptorDrivesBothHalves(Mechanism first, Mechanism second, string secondParamName)
    {
        MechanismParameters? shared = first.Parameters;
        if (shared is null || !ReferenceEquals(shared, second.Parameters) || !shared.AbsorbsTokenOutput)
            return;

        throw new ArgumentException(
            $"The same {shared.GetType().Name} instance drives both mechanisms of this operation. The "
            + "token writes into it, and both halves would absorb into the same managed buffer, so one "
            + "of the two results would be silently discarded. Use a separate parameter object for "
            + "each mechanism.",
            secondParamName);
    }

    // Takes the Mechanism rather than a CKM so the conversion happens once, here, instead of at all
    // ~50 call sites. The cast is meaningful only for mechanisms this enum names: a vendor-defined
    // value lands in `default` and is not gated, which is correct — the policy encodes verdicts about
    // known-weak algorithms, and it has none to offer about a mechanism it has never heard of.
    private void GuardMechanism(Mechanism mechanism)
    {
        if (AllowInsecure) return;

        CKM mechanismType = (CKM)mechanism.Type;

        switch (mechanismType)
        {
            case CKM.CKM_RSA_PKCS:
                throw new InsecureOperationException(mechanismType,
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_MD5_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                throw new InsecureOperationException(mechanismType,
                    "MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too); use CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 instead.");
            case CKM.CKM_MD5:
            case CKM.CKM_SHA_1:
                throw new InsecureOperationException(mechanismType,
                    "MD5 and SHA-1 are broken hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_DES_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
                throw new InsecureOperationException(mechanismType,
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CCM) instead.");
            case CKM.CKM_DES_MAC:
            case CKM.CKM_DES_MAC_GENERAL:
            case CKM.CKM_DES3_MAC:
            case CKM.CKM_DES3_MAC_GENERAL:
                throw new InsecureOperationException(mechanismType,
                    "DES/3DES MAC is weak; use CKM_AES_CMAC or CKM_SHA256_HMAC instead.");
            case CKM.CKM_DES_KEY_GEN:
            case CKM.CKM_DES2_KEY_GEN:
            case CKM.CKM_DES3_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "DES and 3DES key generation produces deprecated keys; use CKM_AES_KEY_GEN instead.");
            case CKM.CKM_DES3_ECB_ENCRYPT_DATA:
            case CKM.CKM_DES3_CBC_ENCRYPT_DATA:
                throw new InsecureOperationException(mechanismType,
                    "DES3 key-derive mechanisms are weak; use CKM_SP800_108-family KDFs or CKM_AES_CBC_ENCRYPT_DATA on a strong base key instead.");
            case CKM.CKM_AES_ECB:
                throw new InsecureOperationException(mechanismType,
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CCM instead.");
            case CKM.CKM_AES_CBC:
            case CKM.CKM_AES_CBC_PAD:
            case CKM.CKM_AES_CTR:
            case CKM.CKM_AES_CTS:
            case CKM.CKM_AES_OFB:
            case CKM.CKM_AES_CFB1:
            case CKM.CKM_AES_CFB8:
            case CKM.CKM_AES_CFB64:
            case CKM.CKM_AES_CFB128:
                throw new InsecureOperationException(mechanismType,
                    "Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. Use CKM_AES_GCM or CKM_AES_CCM. To use these for legacy interop, set Pkcs11Workspace.AllowInsecure = true.");
            case CKM.CKM_RC4:
            case CKM.CKM_RC4_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "RC4 is a broken stream cipher with a biased keystream (prohibited in TLS by RFC 7465); use CKM_AES_GCM.");
            case CKM.CKM_RC2_ECB:
            case CKM.CKM_RC2_CBC:
            case CKM.CKM_RC2_CBC_PAD:
            case CKM.CKM_RC2_MAC:
            case CKM.CKM_RC2_MAC_GENERAL:
            case CKM.CKM_RC2_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "RC2 is a deprecated 40/64-bit-key cipher with known weaknesses; use CKM_AES_GCM.");
            case CKM.CKM_SEED_ECB:
            case CKM.CKM_SEED_CBC:
            case CKM.CKM_SEED_CBC_PAD:
            case CKM.CKM_SEED_MAC:
            case CKM.CKM_SEED_MAC_GENERAL:
            case CKM.CKM_SEED_KEY_GEN:
            case CKM.CKM_SEED_CBC_ENCRYPT_DATA:
            case CKM.CKM_SEED_ECB_ENCRYPT_DATA:
                throw new InsecureOperationException(mechanismType,
                    "SEED is a legacy regional cipher retained only for Korean-standard interop; use CKM_AES_GCM.");
            case CKM.CKM_MD2:
            case CKM.CKM_MD2_HMAC:
            case CKM.CKM_MD2_HMAC_GENERAL:
            case CKM.CKM_MD2_KEY_DERIVATION:
            case CKM.CKM_MD2_RSA_PKCS:
                throw new InsecureOperationException(mechanismType,
                    "MD2 is a broken hash function; use CKM_SHA256 or stronger.");
            case CKM.CKM_RIPEMD128:
            case CKM.CKM_RIPEMD128_HMAC:
            case CKM.CKM_RIPEMD128_HMAC_GENERAL:
            case CKM.CKM_RIPEMD128_RSA_PKCS:
            case CKM.CKM_RIPEMD160:
            case CKM.CKM_RIPEMD160_HMAC:
            case CKM.CKM_RIPEMD160_HMAC_GENERAL:
            case CKM.CKM_RIPEMD160_RSA_PKCS:
                throw new InsecureOperationException(mechanismType,
                    "RIPEMD-128/160 are deprecated hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_SHA_1_HMAC:
            case CKM.CKM_SHA_1_HMAC_GENERAL:
            case CKM.CKM_ECDSA_SHA1:
                throw new InsecureOperationException(mechanismType,
                    "SHA-1 is collision-broken and deprecated in signature/MAC contexts; use CKM_SHA256_HMAC or CKM_ECDSA_SHA256.");
            case CKM.CKM_RSA_X_509:
                throw new InsecureOperationException(mechanismType,
                    "Raw RSA (X.509, no padding) is malleable and forgeable; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_DSA:
            case CKM.CKM_DSA_SHA1:
            case CKM.CKM_DSA_SHA224:
            case CKM.CKM_DSA_SHA256:
            case CKM.CKM_DSA_SHA384:
            case CKM.CKM_DSA_SHA512:
                throw new InsecureOperationException(mechanismType,
                    "DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys; use CKM_ECDSA_SHA256 or CKM_ML_DSA.");
            case CKM.CKM_CAST_ECB:
            case CKM.CKM_CAST_CBC:
            case CKM.CKM_CAST_CBC_PAD:
            case CKM.CKM_CAST_MAC:
            case CKM.CKM_CAST_MAC_GENERAL:
            case CKM.CKM_CAST_KEY_GEN:
            case CKM.CKM_CAST3_ECB:
            case CKM.CKM_CAST3_CBC:
            case CKM.CKM_CAST3_CBC_PAD:
            case CKM.CKM_CAST3_MAC:
            case CKM.CKM_CAST3_MAC_GENERAL:
            case CKM.CKM_CAST3_KEY_GEN:
            // CKM_CAST5_* are the old names for CKM_CAST128_* (identical enum values), so the
            // CAST128 labels below also match CAST5 calls.
            case CKM.CKM_CAST128_ECB:
            case CKM.CKM_CAST128_CBC:
            case CKM.CKM_CAST128_CBC_PAD:
            case CKM.CKM_CAST128_MAC:
            case CKM.CKM_CAST128_MAC_GENERAL:
            case CKM.CKM_CAST128_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            case CKM.CKM_RC5_ECB:
            case CKM.CKM_RC5_CBC:
            case CKM.CKM_RC5_CBC_PAD:
            case CKM.CKM_RC5_MAC:
            case CKM.CKM_RC5_MAC_GENERAL:
            case CKM.CKM_RC5_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            case CKM.CKM_BLOWFISH_CBC:
            case CKM.CKM_BLOWFISH_CBC_PAD:
            case CKM.CKM_BLOWFISH_KEY_GEN:
                throw new InsecureOperationException(mechanismType,
                    "Blowfish is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            case CKM.CKM_SKIPJACK_KEY_GEN:
            case CKM.CKM_SKIPJACK_ECB64:
            case CKM.CKM_SKIPJACK_CBC64:
            case CKM.CKM_SKIPJACK_OFB64:
            case CKM.CKM_SKIPJACK_CFB64:
            case CKM.CKM_SKIPJACK_CFB32:
            case CKM.CKM_SKIPJACK_CFB16:
            case CKM.CKM_SKIPJACK_CFB8:
            case CKM.CKM_SKIPJACK_WRAP:
            case CKM.CKM_SKIPJACK_PRIVATE_WRAP:
            case CKM.CKM_SKIPJACK_RELAYX:
                throw new InsecureOperationException(mechanismType,
                    "SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses; use CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping).");
            default:
                return;
        }
    }

    /// <summary>
    /// Secure-defaults gate for key-pair generation strength. RSA moduli below 2048 bits are under the
    /// NIST SP 800-131A floor and are refused unless <see cref="AllowInsecure"/> is set — the same
    /// opt-in model as the weak-mechanism gate, so a sub-2048 RSA key is a deliberate, audited choice
    /// (e.g. legacy interop) rather than a silent default. Reads <c>CKA_MODULUS_BITS</c> from the public
    /// template; non-RSA mechanisms and templates without the attribute are not affected.
    /// </summary>
    private void GuardKeyPairStrength(CKM mechanism, List<ObjectAttribute> publicKeyAttributes)
    {
        if (AllowInsecure) return;
        if (mechanism is not (CKM.CKM_RSA_PKCS_KEY_PAIR_GEN or CKM.CKM_RSA_X9_31_KEY_PAIR_GEN))
            return;

        // Only the first CKA_MODULUS_BITS is consulted, as before: a template carrying two is
        // malformed, and which one the token would honour is not ours to decide.
        ObjectAttribute? modulusBits =
            publicKeyAttributes.FirstOrDefault(a => (CKA)a.Type == CKA.CKA_MODULUS_BITS);
        if (modulusBits is null)
            return;

        ulong bits = modulusBits.GetValueAsUlong();
        if (bits < 2048)
            throw new InsecureOperationException(
                $"RSA-{bits} is below the NIST SP 800-131A 2048-bit minimum. Set Pkcs11Workspace.AllowInsecure " +
                "to opt in (e.g. legacy interop), or generate a key of at least 2048 bits.");
    }

    #region IDisposable

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        Log.SessionTrace(_logger, (ulong)_sessionId, "Dispose1");

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    private void Dispose(bool disposing)
    {
        Log.SessionTrace(_logger, (ulong)_sessionId, "Dispose2");

        // Releasing the handle issues C_CloseSession, so disposal has to hold the same lock every
        // native-touching method holds: session ids cross the P/Invoke boundary by value, and the
        // SafeHandle's ref-counting protects the handle object, not the session behind it. Without
        // this, a Dispose on one thread closes the session out from under a C_Sign in flight on
        // another — undefined behaviour at the boundary.
        //
        // It waits for the lock rather than going through AcquireExclusive, which throws on
        // cross-thread contention. Dispose usually runs from a `using` that is already unwinding,
        // where a throw would replace the exception that started the unwind with one about closing
        // a session — the same reason ReadOnlyDisposableList records its release failures instead
        // of throwing them. Waiting is bounded in practice: the lock is only ever held for the
        // length of one native call, and the sole nesting is _busyLock -> the library's session
        // tracker, never the reverse, so there is no ordering cycle to deadlock on. Monitor is
        // reentrant, so disposing from inside an operation on this thread still closes.
        bool lockTaken = false;
        try
        {
            Monitor.Enter(_busyLock, ref lockTaken);

            if (_disposed)
                return;

            // Managed cleanup — release the session handle (SafeHandle releases via C_CloseSession).
            // Honour _closeWhenDisposed: only close if the caller wants automatic close on dispose.
            if (disposing && _closeWhenDisposed)
            {
                _sessionHandle?.Dispose();
                _sessionHandle = null!;
            }

            // No unmanaged resources owned by Session directly — Pkcs11SessionHandle owns the
            // session ID, and Pkcs11ModuleHandle (held transitively via _pkcs11Library) owns the
            // library module. Both are SafeHandles and run their own critical finalizers.
            _disposed = true;
        }
        finally
        {
            if (lockTaken)
                Monitor.Exit(_busyLock);
        }
    }

    // NOTE: ~Session() finalizer intentionally removed.
    // Pkcs11SessionHandle is a SafeHandle (CriticalFinalizerObject) and runs its own critical
    // finalizer after regular finalizers, which is exactly the correct order for native-handle
    // cleanup.  The Pkcs11SessionHandle also holds a strong reference to LowLevelPkcs11Library,
    // keeping the library's Pkcs11ModuleHandle reachable for as long as any session handle lives.

    #endregion

    /// <summary>
    /// Creates a new object
    /// </summary>
    /// <param name="attributes">Object attributes</param>
    /// <returns>Handle of created object</returns>
    public ObjectHandle CreateObject(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "CreateObject");

        // Any object class may arrive here, so the refusal applies but key defaults do not.
        GuardInsecureKeyAttributes(attributes);

        NativeCULong objectId = CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes, out NativeCULong templateLength);

        CKR rv = _pkcs11Library.C_CreateObject(_sessionId, template, templateLength, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCreateObject);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="objectHandle">Handle of object to be copied</param>
    /// <param name="attributes">New values for any attributes of the object that can ordinarily be modified</param>
    /// <returns>Handle of copied object</returns>
    public ObjectHandle CopyObject(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "CopyObject");

        // A copy can weaken the original's protection, so the same refusal applies.
        GuardInsecureKeyAttributes(attributes);


        NativeCULong objectId = CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes, out NativeCULong templateLength);

        CKR rv = _pkcs11Library.C_CopyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, templateLength, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCopyObject);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="objectHandle">Handle of object to be destroyed</param>
    public void DestroyObject(ObjectHandle objectHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DestroyObject");


        CKR rv = _pkcs11Library.C_DestroyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDestroyObject);
    }

    /// <summary>
    /// Gets the size of an object in bytes.
    /// </summary>
    /// <param name="objectHandle">Handle of object</param>
    /// <returns>Size of an object in bytes</returns>
    public ulong GetObjectSize(ObjectHandle objectHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetObjectSize");


        NativeCULong objectSize = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetObjectSize(_sessionId, (NativeCULong)(objectHandle.ObjectId), ref objectSize);
        Pkcs11Exception.ThrowIfError(rv, OpGetObjectSize);

        return (ulong)(objectSize);
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be read</param>
    /// <param name="attributes">List of attributes that should be read</param>
    /// <returns>Object attributes</returns>
    public ReadOnlyDisposableList<ObjectAttribute> GetAttributeValue(ObjectHandle objectHandle, List<CKA> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue1");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        List<ulong> ulongs = [];
        foreach (CKA attribute in attributes)
            ulongs.Add((ulong)attribute.ToCULong());

        return GetAttributeValue(objectHandle, ulongs);
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be read</param>
    /// <param name="attributes">List of attributes that should be read</param>
    /// <returns>Object attributes</returns>
    public ReadOnlyDisposableList<ObjectAttribute> GetAttributeValue(ObjectHandle objectHandle, List<ulong> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue2");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        // Prepare array of CK_ATTRIBUTEs. These are type-only: the first call asks the module how long
        // each value is, so the template carries no values and needs no buffers.
        //
        // Built directly rather than through ObjectAttribute, which is IDisposable and was being
        // constructed here only to have its struct copied out and the wrapper dropped. Adding a `using`
        // would have been the wrong repair: the copy in the template shares the wrapper's pointer, so
        // disposing would leave the template pointing at freed memory the moment a type-only attribute
        // ever allocated one. Not creating the disposable avoids the question.
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
        {
            template[i] = new CK_ATTRIBUTE
            {
                type = (NativeCULong)attributes[i],
                value = IntPtr.Zero,
                valueLen = (NativeCULong)0,
            };
        }

        // The size actually allocated for each attribute, kept so the post-call length can be checked
        // against it rather than trusted — see GuardReportedLength.
        NativeCULong[] allocatedLen = new NativeCULong[template.Length];

        // Every block handed to the module. Ownership passes to the ObjectAttributes only at the very
        // end, so until then a failure anywhere below has to free them here or they leak — which the
        // fatal-return paths and the malformed-nested-template throw did before this.
        List<IntPtr> allocatedBlocks = [];

        // Where each nested attribute sits inside its parent block, and the size allocated for it, so
        // the third call's lengths can be checked the same way.
        List<(IntPtr Pointer, NativeCULong Allocated)> nestedAllocations = [];

        // Determine size of attribute values
        CKR rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
        if (IsGetAttributeValueFatal(rv))
            Pkcs11Exception.ThrowIfError(rv, OpGetAttributeValue);

        // Allocate memory for each attribute
        for (int i = 0; i < template.Length; i++)
        {
            // PKCS#11 v2.20 page 133:
            // If the specified attribute (i.e., the attribute specified by the type field) for the object
            // cannot be revealed because the object is sensitive or unextractable, then the
            // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
            // CK_LONG, it holds -1).
            // Compare against the canonical sentinel (NativeCULong.MaxValue = uint.MaxValue on Windows,
            // ulong.MaxValue on Linux-LP64), as ObjectAttribute.CannotBeRead does. The previous
            // `.Value != nuint.MaxValue` only matched on Linux: on Win64 nuint is 8 bytes but CK_ULONG
            // is 4, so the -1 sentinel went unrecognized and (int)valueLen overflowed.
            if (template[i].valueLen != NativeCULong.MaxValue)
            {
                allocatedLen[i] = template[i].valueLen;
                template[i].value = UnmanagedMemory.Allocate((int)(template[i].valueLen));
                allocatedBlocks.Add(template[i].value);
            }
        }

        try
        {
            // Read values of attributes
            rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
            if (IsGetAttributeValueFatal(rv))
                Pkcs11Exception.ThrowIfError(rv, OpGetAttributeValue);

            for (int i = 0; i < template.Length; i++)
                GuardReportedLength(in template[i], allocatedLen[i]);

            // Third call to C_GetAttributeValue is needed if any of the attributes is an array attribute
            bool thirdCallNeeded = false;
            for (int i = 0; i < template.Length; i++)
            {
                if (IsNestedAttributeTemplate(template[i].type))
                {
                    // PKCS#11 v2.20 page 133:
                    // If the specified attribute (i.e., the attribute specified by the type field) for the object
                    // cannot be revealed because the object is sensitive or unextractable, then the
                    // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
                    // CK_LONG, it holds -1).
                    if (template[i].valueLen == NativeCULong.MaxValue)
                        continue;

                    int ckAttributeSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
                    int nestedAttrCount = (int)(template[i].valueLen) / ckAttributeSize;
                    int nestedAttrCountMod = (int)(template[i].valueLen) % ckAttributeSize;

                    if (nestedAttrCountMod != 0)
                        throw new AttributeValueException((ulong)template[i].type);

                    if (nestedAttrCount == 0)
                    {
                        continue;
                    }
                    else
                    {
                        thirdCallNeeded = true;

                        // Allocate memory for each nested attribute
                        for (int j = 0; j < nestedAttrCount; j++)
                        {
                            IntPtr tempPointer = new(template[i].value.ToInt64() + (j * ckAttributeSize));
                            CK_ATTRIBUTE tempAttribute = UnmanagedMemory.Read<CK_ATTRIBUTE>(tempPointer);

                            if (tempAttribute.valueLen != NativeCULong.MaxValue)
                            {
                                tempAttribute.value = UnmanagedMemory.Allocate((int)(tempAttribute.valueLen));
                                allocatedBlocks.Add(tempAttribute.value);
                                nestedAllocations.Add((tempPointer, tempAttribute.valueLen));
                            }

                            UnmanagedMemory.Write(tempPointer, in tempAttribute);
                        }
                    }
                }
            }

            // Read values of all nested attributes
            if (thirdCallNeeded)
            {
                rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
                if (IsGetAttributeValueFatal(rv))
                    Pkcs11Exception.ThrowIfError(rv, OpGetAttributeValue);

                // The nested attributes are read back the same way and are equally able to lie.
                foreach ((IntPtr pointer, NativeCULong allocated) in nestedAllocations)
                    GuardReportedLength(UnmanagedMemory.Read<CK_ATTRIBUTE>(pointer), allocated);
            }
        }
        catch
        {
            // Freed through a span so that Free's write-back lands in the list. Free nulls the pointer
            // it is given and returns early on a null one — that pair is its double-free guard, and
            // handing it a copy of each entry threw the guard away while looking like it was using it.
            Span<IntPtr> blocks = CollectionsMarshal.AsSpan(allocatedBlocks);
            for (int i = 0; i < blocks.Length; i++)
                UnmanagedMemory.Free(ref blocks[i]);
            throw;
        }

        // Convert CK_ATTRIBUTEs to ObjectAttributes. Deliberately outside the try: from here the
        // ObjectAttributes own the blocks, and freeing them here too would be a double free.
        List<ObjectAttribute> outAttributes = [];
        for (int i = 0; i < template.Length; i++)
            outAttributes.Add(new ObjectAttribute(template[i]));

        // The blocks belong to the caller from here; the returned list is what releases them.
        return new ReadOnlyDisposableList<ObjectAttribute>(outAttributes);
    }

    /// <summary>
    /// Rejects a post-call <c>ulValueLen</c> larger than the buffer that was allocated to hold it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two-call idiom sizes each buffer from the length the module reports on the first call and
    /// hands it back on the second. Nothing obliges the module to report the same length twice, and
    /// every reader on <c>ObjectAttribute</c> sizes its read from whatever came back last — so a module
    /// that inflates the length, by bug or by design, walks those reads off the end of the allocation
    /// and returns whatever unmanaged memory follows it to the caller.
    /// </para>
    /// <para>
    /// The write direction is already covered: the buffer is the module's to fill, and the checked
    /// <c>NativeCULong</c> conversions catch a length that overflows outright. This is the
    /// in-range-but-oversized case, which nothing else catches and which fails silently.
    /// </para>
    /// </remarks>
    private static void GuardReportedLength(in CK_ATTRIBUTE attribute, NativeCULong allocated)
    {
        // The -1 sentinel means sensitive or unextractable; no buffer was allocated and none is read.
        if (attribute.valueLen == NativeCULong.MaxValue)
            return;

        if (attribute.valueLen <= allocated)
            return;

        throw new AttributeValueException((ulong)attribute.type,
            $"The PKCS#11 module reported attribute 0x{(ulong)attribute.type:X} as "
            + $"{(ulong)attribute.valueLen} bytes after being given a {(ulong)allocated}-byte buffer "
            + "sized from its own earlier answer. Reading the value at the reported length would read "
            + "past the allocation, so it was refused.");
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be modified</param>
    /// <param name="attributes">List of attributes that should be modified</param>
    public void SetAttributeValue(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetAttributeValue");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;

        CKR rv = _pkcs11Library.C_SetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
        Pkcs11Exception.ThrowIfError(rv, OpSetAttributeValue);
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    public void FindObjectsInit(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjectsInit");

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes, out NativeCULong templateLength);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template, templateLength);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="objectCount">Maximum number of object handles to be returned</param>
    /// <returns>Found object handles</returns>
    public List<ObjectHandle> FindObjects(int objectCount)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjects");

        List<ObjectHandle> foundObjects = [];

        NativeCULong[] objects = new NativeCULong[objectCount];
        NativeCULong foundObjectsCount = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_FindObjects(_sessionId, objects, (NativeCULong)(objectCount), ref foundObjectsCount);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

        for (int i = 0; i < (int)(foundObjectsCount); i++)
            foundObjects.Add(new ObjectHandle((ulong)objects[i]));

        return foundObjects;
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    public void FindObjectsFinal()
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjectsFinal");

        CKR rv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsFinal);
    }

    /// <summary>
    /// Searches for all token and session objects that match provided attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    /// <returns>Handles of found objects</returns>
    public List<ObjectHandle> FindAllObjects(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindAllObjects");

        List<ObjectHandle> foundObjects = [];

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes, out NativeCULong templateLength);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template, templateLength);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);

        try
        {
            NativeCULong objectsLength = (NativeCULong)256;
            NativeCULong[] objects = new NativeCULong[(int)objectsLength];
            NativeCULong objectCount = objectsLength;
            while (objectCount == objectsLength)
            {
                rv = _pkcs11Library.C_FindObjects(_sessionId, objects, objectsLength, ref objectCount);
                Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

                for (int i = 0; i < (int)(objectCount); i++)
                    foundObjects.Add(new ObjectHandle((ulong)objects[i]));
            }
        }
        finally
        {
            // Best-effort finalize. Always runs so a mid-search exception cannot leave the
            // session wedged in "find active" state — the next C_FindObjectsInit would
            // otherwise fail with CKR_OPERATION_ACTIVE. Tolerate the rv: on the exception
            // unwind path we must not mask the original exception, and the session may
            // already be in a state where finalize fails harmlessly.
            CKR finalRv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                _logger.LogWarning("Session({SessionId})::FindAllObjects: C_FindObjectsFinal returned {Rv}", _sessionId, finalRv);
        }

        return foundObjects;
    }

    /// <summary>
    /// Returns <c>true</c> when a <c>C_GetAttributeValue</c> return value should
    /// terminate the read with an exception. The PKCS#11 spec defines
    /// <c>CKR_ATTRIBUTE_SENSITIVE</c> ("the attribute exists but cannot be read") and
    /// <c>CKR_ATTRIBUTE_TYPE_INVALID</c> ("the attribute does not apply to this object")
    /// as non-fatal indicators that should be reported back to the caller via the
    /// attribute's value-length sentinel rather than thrown.
    /// </summary>
    private static bool IsGetAttributeValueFatal(CKR rv)
        => rv is not CKR.CKR_OK
        and not CKR.CKR_ATTRIBUTE_SENSITIVE
        and not CKR.CKR_ATTRIBUTE_TYPE_INVALID;

    /// <summary>
    /// True when the attribute type is one of the three PKCS#11 attributes whose
    /// value is an array of nested <c>CK_ATTRIBUTE</c>s and therefore requires the
    /// third <c>C_GetAttributeValue</c> pass to fill each inner buffer.
    /// </summary>
    /// <remarks>
    /// The PKCS#11 <c>CKF_ARRAY_ATTRIBUTE</c> high bit (0x40000000) alone is not a
    /// sufficient indicator — <c>CKA_ALLOWED_MECHANISMS</c> also carries that bit
    /// but its value is an array of <c>CKM</c> ids, not nested attributes.
    /// </remarks>
    private static bool IsNestedAttributeTemplate(NativeCULong type)
        => (CKA)(ulong)type switch
        {
            CKA.CKA_WRAP_TEMPLATE => true,
            CKA.CKA_UNWRAP_TEMPLATE => true,
            CKA.CKA_DERIVE_TEMPLATE => true,
            _ => false,
        };

    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="mechanism">Generation mechanism</param>
    /// <param name="attributes">Attributes of the new key or set of domain parameters</param>
    /// <returns>Handle of the new key or set of domain parameters</returns>
    public ObjectHandle GenerateKey(Mechanism mechanism, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKey");

        // A secret key: refuse a deliberately weakened template, and supply the secure defaults when
        // the caller stated nothing — the same treatment DeriveKey and UnwrapKey already gave.
        using ReadOnlyDisposableList<ObjectAttribute> generatedDefaults = BuildSecureKeyDefaults(attributes);
        if (generatedDefaults.Count > 0)
        {
            attributes = attributes is null ? [] : [.. attributes];
            attributes.AddRange(generatedDefaults);
        }

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes, out NativeCULong templateLength);

        NativeCULong keyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKey(_sessionId, ref ckMechanism, template, templateLength, ref keyId);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKey);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)keyId);
    }

    /// <summary>
    /// Generates a public/private key pair, creating new key objects
    /// </summary>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="publicKeyAttributes">Attributes of the public key</param>
    /// <param name="privateKeyAttributes">Attributes of the private key</param>
    /// <param name="publicKeyHandle">Handle of the new public key</param>
    /// <param name="privateKeyHandle">Handle of the new private key</param>
    public void GenerateKeyPair(Mechanism mechanism, List<ObjectAttribute> publicKeyAttributes, List<ObjectAttribute> privateKeyAttributes, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);
        GuardKeyPairStrength((CKM)mechanism.Type, publicKeyAttributes);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKeyPair");

        // The private half only. CKA_SENSITIVE / CKA_EXTRACTABLE do not belong on a public key, so
        // seeding them there would be rejected by the token; the refusal alone is enough.
        using ReadOnlyDisposableList<ObjectAttribute> privateDefaults = BuildSecureKeyDefaults(privateKeyAttributes);
        if (privateDefaults.Count > 0)
        {
            privateKeyAttributes = [.. privateKeyAttributes];
            privateKeyAttributes.AddRange(privateDefaults);
        }

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CK_ATTRIBUTE[]? publicKeyTemplate = BuildTemplate(publicKeyAttributes, out NativeCULong publicKeyTemplateLength);
        CK_ATTRIBUTE[]? privateKeyTemplate = BuildTemplate(privateKeyAttributes, out NativeCULong privateKeyTemplateLength);

        NativeCULong publicKeyId = CK.CK_INVALID_HANDLE;
        NativeCULong privateKeyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKeyPair(_sessionId, ref ckMechanism, publicKeyTemplate, publicKeyTemplateLength, privateKeyTemplate, privateKeyTemplateLength, ref publicKeyId, ref privateKeyId);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKeyPair);

        mechanism.AbsorbOutput(mechParams);

        publicKeyHandle = new ObjectHandle((ulong)publicKeyId);
        privateKeyHandle = new ObjectHandle((ulong)privateKeyId);
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKeyHandle">Handle of wrapping key</param>
    /// <param name="keyHandle">Handle of key to be wrapped</param>
    /// <returns>Wrapped key</returns>
    public byte[] WrapKey(Mechanism mechanism, ObjectHandle wrappingKeyHandle, ObjectHandle keyHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        byte[] wrappedKey = CallWithLengthProbe(
            (byte[]? buf, ref NativeCULong len) => _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), buf, ref len),
            OpWrapKey);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return wrappedKey;
    }

    /// <summary>
    /// Unwraps a wrapped key using the given unwrapping key and mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Key-unwrap mechanism.</param>
    /// <param name="unwrappingKeyHandle">Handle of the unwrapping key (private RSA, AES-WRAP key, etc.).</param>
    /// <param name="wrappedKey">Wrapped key bytes to unwrap.</param>
    /// <param name="attributes">Template for the resulting unwrapped key.</param>
    /// <returns>Handle of the newly unwrapped key.</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, ReadOnlySpan<byte> wrappedKey, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(attributes);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = wrappedKey.ToArray();
        return UnwrapKey(mechanism, unwrappingKeyHandle, buffer, attributes);
    }

    /// <summary>
    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
    /// </summary>
    /// <param name="mechanism">Unwrapping mechanism</param>
    /// <param name="unwrappingKeyHandle">Handle of unwrapping key</param>
    /// <param name="wrappedKey">Wrapped key</param>
    /// <param name="attributes">Attributes for unwrapped key</param>
    /// <returns>Handle of unwrapped key</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, byte[] wrappedKey, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        ArgumentNullException.ThrowIfNull(wrappedKey);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        // Unwrapping decrypts a key blob into a new token object. Without secure defaults a caller
        // could land an extractable, non-sensitive key — silently downgrading the posture the key
        // template builders establish. Append CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the
        // caller omitted them; an explicit insecure value requires AllowInsecure (throws otherwise).
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults, out NativeCULong templateLen);

        NativeCULong unwrappedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, ref ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, (NativeCULong)(wrappedKey.Length), template, templateLen, ref unwrappedKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKey);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)unwrappedKey);
    }

    /// <summary>
    /// Refuses a template that would make key material readable in plaintext, unless the caller has
    /// opted in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only <c>CKA_SENSITIVE=false</c> is refused. <c>CKA_EXTRACTABLE=true</c> is not: an extractable
    /// key can be <i>wrapped</i> — exported encrypted under a KEK — which is the standard way to back
    /// up and transport keys, and PKCS#11 requires the attribute for it. Demanding an "insecure"
    /// opt-in to use key wrapping at all would misdescribe a safe operation. The value still never
    /// leaves in the clear, which is what <c>CKA_SENSITIVE</c> governs and what this refuses.
    /// </para>
    /// <para>
    /// Non-extractable remains the <i>default</i> — <see cref="BuildSecureKeyDefaults"/> still supplies
    /// <c>CKA_EXTRACTABLE=false</c> when the caller says nothing. Asking for extractable is allowed;
    /// getting it by omission is not.
    /// </para>
    /// Check only — it adds nothing — so it is safe on any object class, including public keys and
    /// non-key objects where <c>CKA_SENSITIVE</c>/<c>CKA_EXTRACTABLE</c> defaults would be wrong or
    /// rejected outright. Every path that creates a token object runs this; the ones that create a
    /// secret or private key additionally run <see cref="BuildSecureKeyDefaults"/> to supply the
    /// defaults when the caller stated nothing.
    /// </remarks>
    private void GuardInsecureKeyAttributes(List<ObjectAttribute>? attributes)
    {
        if (attributes is null) return;

        // The opt-in is checked up front rather than per-attribute, matching GuardMechanism and
        // GuardKeyPairStrength. It also stops the guard from reading a value it has already decided not
        // to police: with AllowInsecure set there is no verdict to reach, so there is no reason to
        // parse a caller's CKA_SENSITIVE and risk throwing over its encoding instead.
        if (AllowInsecure) return;

        if (attributes.Any(a => a.Type == (ulong)CKA.CKA_SENSITIVE && !a.GetValueAsBool()))
            throw new InsecureOperationException(
                "Creating a key with CKA_SENSITIVE=false would create a non-sensitive key whose value can be read off the token. " +
                "Pass AllowInsecure (or use AllowInsecureScope) to override.");
    }

    /// <summary>
    /// Runs <see cref="GuardInsecureKeyAttributes"/>, then returns the secure-default attributes to
    /// append for any the caller omitted — <c>CKA_SENSITIVE=true</c> and <c>CKA_EXTRACTABLE=false</c>.
    /// </summary>
    /// <remarks>
    /// Used by the paths that create a secret or private key from a template, so they all start from
    /// the same posture. The returned attributes own unmanaged buffers and must be disposed by the
    /// caller. Note the asymmetry with the refusal: <c>CKA_EXTRACTABLE=false</c> is supplied as a
    /// default here, but an explicit <c>CKA_EXTRACTABLE=true</c> is not refused — only
    /// <c>CKA_SENSITIVE=false</c> is.
    /// </remarks>
    private ReadOnlyDisposableList<ObjectAttribute> BuildSecureKeyDefaults(List<ObjectAttribute>? attributes)
    {
        GuardInsecureKeyAttributes(attributes);

        bool hasSensitive = attributes?.Any(a => a.Type == (ulong)CKA.CKA_SENSITIVE) ?? false;
        bool hasExtractable = attributes?.Any(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE) ?? false;

        List<ObjectAttribute> added = [];
        if (!hasSensitive)
            added.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        if (!hasExtractable)
            added.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));

        // The caller owns what comes back — these are attributes this method created, not the
        // caller's own — so hand back something that says so and can be released with a `using`.
        return new ReadOnlyDisposableList<ObjectAttribute>(added);
    }

    // ---- Marshalling helpers (shared by the wrapper methods) ----

    /// <summary>
    /// Marshals a managed attribute list into a <c>CK_ATTRIBUTE[]</c> template, returning <c>null</c>
    /// (and length 0) when <paramref name="attributes"/> is <c>null</c> — the PKCS#11 convention of a
    /// null template meaning "no attributes".
    /// </summary>
    private static CK_ATTRIBUTE[]? BuildTemplate(List<ObjectAttribute>? attributes, out NativeCULong length)
    {
        if (attributes is null)
        {
            length = (NativeCULong)0;
            return null;
        }

        length = (NativeCULong)attributes.Count;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;
        return template;
    }

    /// <summary>
    /// Builds a key-creation template from the caller's <paramref name="attributes"/> followed by the
    /// appended <paramref name="secureDefaults"/>. Returns <c>null</c> (length 0) only when both are
    /// empty, matching the "null template = no attributes" convention.
    /// </summary>
    private static CK_ATTRIBUTE[]? BuildTemplateWithDefaults(List<ObjectAttribute>? attributes, ReadOnlyDisposableList<ObjectAttribute> secureDefaults, out NativeCULong length)
    {
        int attrCount = attributes?.Count ?? 0;
        int total = attrCount + secureDefaults.Count;
        if (total == 0)
        {
            length = (NativeCULong)0;
            return null;
        }

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[total];
        int idx = 0;
        for (int i = 0; i < attrCount; i++)
            template[idx++] = attributes![i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;
        length = (NativeCULong)total;
        return template;
    }

    /// <summary>
    /// Interprets a verify return value: <c>true</c> on <see cref="CKR.CKR_OK"/>, <c>false</c> on
    /// <see cref="CKR.CKR_SIGNATURE_INVALID"/>, and throws <see cref="Pkcs11Exception"/> for any other
    /// code (tagged with <paramref name="operation"/>).
    /// </summary>
    private static bool IsVerified(CKR rv, string operation)
    {
        if (rv == CKR.CKR_OK) return true;
        if (rv == CKR.CKR_SIGNATURE_INVALID) return false;
        throw Pkcs11Exception.Create(rv, operation);
    }

    /// <summary>One step of a Cryptoki two-call length probe: invoke with a null buffer to learn the
    /// size, then again with the allocated buffer.</summary>
    private delegate CKR LengthProbedCall(byte[]? buffer, ref NativeCULong length);

    /// <summary>
    /// Runs the standard PKCS#11 two-call pattern — probe the output length with a null buffer,
    /// allocate, fill, then trim to the reported length — throwing on any non-OK return from either
    /// call (both tagged with <paramref name="operation"/>).
    /// </summary>
    private static byte[] CallWithLengthProbe(LengthProbedCall call, string operation)
    {
        NativeCULong length = (NativeCULong)0;
        CKR rv = call(null, ref length);
        Pkcs11Exception.ThrowIfError(rv, operation);

        byte[] buffer = new byte[(int)length];
        rv = call(buffer, ref length);
        Pkcs11Exception.ThrowIfError(rv, operation);

        if (buffer.Length != (int)length)
            Array.Resize(ref buffer, (int)length);
        return buffer;
    }

    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Encrypt(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be encrypted</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt1");

        ArgumentNullException.ThrowIfNull(data);

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpEncryptInit);

        // Size the output for the largest single-block expansion a symmetric mechanism adds — a full
        // block of PKCS padding (AES block = 16) or a 16-byte AEAD tag — so block and AEAD ciphers
        // finish in one C_Encrypt without a null-length probe (which makes some AEAD tokens run the
        // whole operation on the probe). This also sidesteps NSS softoken's broken single-part CBC-PAD
        // path, whose short-buffer C_Encrypt feeds the input through EncryptUpdate/Final and does not
        // report the required length. RSA and other output-larger-than-input mechanisms still grow via
        // the CKR_BUFFER_TOO_SMALL retry below.
        byte[] encryptedData = new byte[data.Length + 16];
        NativeCULong encryptedDataLen = (NativeCULong)encryptedData.Length;
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, encryptedData, ref encryptedDataLen);

        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            encryptedData = new byte[(int)encryptedDataLen];
            rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, encryptedData, ref encryptedDataLen);

            // PKCS#11 v3.2 §5.2 requires CKR_BUFFER_TOO_SMALL to leave the operation active for a retry.
            // NSS softoken's classic C_Encrypt violates this — it terminates the operation, so the retry
            // above returns CKR_OPERATION_NOT_INITIALIZED. Recover by re-initializing, probing the length
            // with a NULL buffer, then encrypting once. Reachable only for output-larger-than-input
            // mechanisms (e.g. RSA) that exceed the padded buffer above; unreachable on spec-compliant
            // tokens, whose retry already returned CKR_OK.
            if (rv == CKR.CKR_OPERATION_NOT_INITIALIZED)
            {
                rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
                Pkcs11Exception.ThrowIfError(rv, OpEncryptInit);

                NativeCULong probeLen = (NativeCULong)0;
                rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, null, ref probeLen);
                Pkcs11Exception.ThrowIfError(rv, OpEncrypt);

                encryptedData = new byte[(int)probeLen];
                encryptedDataLen = probeLen;
                rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, encryptedData, ref encryptedDataLen);
            }
        }

        Pkcs11Exception.ThrowIfError(rv, OpEncrypt);

        // Inside the scope's lifetime: the parameter block the token may have written into (an AEAD
        // IV, say) is still allocated. After `scope` is disposed the bytes are zeroized and freed.
        mechanism.AbsorbOutput(mechParams);

        if (encryptedData.Length != (int)encryptedDataLen)
            Array.Resize(ref encryptedData, (int)encryptedDataLen);

        return encryptedData;
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        Encrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpEncryptInit);

        bool finalized = false;
        try
        {
            byte[] part = new byte[bufferLength];
            byte[] encryptedPart = new byte[bufferLength];
            NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                encryptedPartLen = (NativeCULong)(encryptedPart.Length);
                rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, OpEncryptUpdate);

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    encryptedPart = new byte[(int)encryptedPartLen];

                    rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                    Pkcs11Exception.ThrowIfError(rv, OpEncryptUpdate);
                }

                outputStream.Write(encryptedPart, 0, (int)(encryptedPartLen));
            }

            byte[]? lastEncryptedPart = null;
            NativeCULong lastEncryptedPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);

            lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);
            finalized = true;

            mechanism.AbsorbOutput(mechParams);

            if (lastEncryptedPartLen > (NativeCULong)0)
                outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_ENCRYPT, "Encrypt");
        }
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD API
    /// (<see cref="MessageEncrypt"/> / <see cref="MessageDecrypt"/> use it). False on
    /// v2.40 libraries — callers must use <see cref="Encrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> / <see cref="Decrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>
    /// with the legacy CK_GCM_PARAMS / CK_CCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS
    /// instead.
    /// </summary>
    public bool SupportsMessageApi => _pkcs11Library.IsMessageApiSupported;

    /// <summary>
    /// One-shot AEAD encrypt via the PKCS#11 v3.0 message-based API
    /// (C_MessageEncryptInit + C_EncryptMessage + C_MessageEncryptFinal). The per-message
    /// nonce / IV / tag flow lives entirely in <paramref name="messageParams"/>; the
    /// authentication tag is read back through the wrapper's <c>CopyTagTo</c> /
    /// <c>CopyMacTo</c> method after this call.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism (CKM_AES_GCM / CKM_AES_CCM / CKM_CHACHA20_POLY1305 / CKM_SALSA20_POLY1305).</param>
    /// <param name="keyHandle">Symmetric key handle.</param>
    /// <param name="messageParams">Per-message parameters (e.g. <see cref="CkmGcmMessageParams"/>).</param>
    /// <param name="associatedData">Optional Additional Authenticated Data.</param>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <returns>Ciphertext (without the tag — tag is in <paramref name="messageParams"/>).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> when the loaded library is v2.40.</exception>
    public byte[] MessageEncrypt(
        Mechanism mechanism,
        ObjectHandle keyHandle,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageEncrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        CKR rv = _pkcs11Library.C_MessageEncryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageEncryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            object paramsStruct = messageParams.BuildMarshalable(scope);
            int paramsSize = UnmanagedMemory.SizeOf(paramsStruct.GetType());
            IntPtr paramsPtr = scope.Allocate(paramsSize);
            UnmanagedMemory.Write(paramsPtr, paramsStruct);

            byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();
            byte[] pt = plaintext.ToArray();

            NativeCULong ctLen = (NativeCULong)0;
            rv = _pkcs11Library.C_EncryptMessage(
                _sessionId, paramsPtr, (NativeCULong)paramsSize,
                aad, (NativeCULong)aad.Length,
                pt, (NativeCULong)pt.Length,
                null!, ref ctLen);
            Pkcs11Exception.ThrowIfError(rv, "C_EncryptMessage (length probe)");

            byte[] ct = new byte[(int)ctLen];
            rv = _pkcs11Library.C_EncryptMessage(
                _sessionId, paramsPtr, (NativeCULong)paramsSize,
                aad, (NativeCULong)aad.Length,
                pt, (NativeCULong)pt.Length,
                ct, ref ctLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptMessage);

            // The token wrote the authentication tag into the scope-owned block; copy it back into
            // the wrapper before `scope` is disposed and the bytes are zeroized.
            messageParams.AbsorbOutput(paramsStruct);

            if (ct.Length != (int)ctLen)
                Array.Resize(ref ct, (int)ctLen);

            return ct;
        }
        finally
        {
            CKR finalRv = _pkcs11Library.C_MessageEncryptFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                _logger.LogWarning("C_MessageEncryptFinal returned {Rv}", finalRv);
        }
    }

    /// <summary>
    /// Decrypts <paramref name="encryptedData"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The decryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to decrypt with.</param>
    /// <param name="encryptedData">Ciphertext to decrypt.</param>
    /// <returns>A freshly-allocated byte array containing the plaintext.</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        byte[] buffer = encryptedData.ToArray();
        return Decrypt(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Decrypts single-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="encryptedData">Data to be decrypted</param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] encryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt1");

        ArgumentNullException.ThrowIfNull(encryptedData);

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDecryptInit);

        // Use input length as the initial output buffer size — avoids a null-probe call
        // that causes AEAD tokens (e.g. SoftHSM2) to run full tag verification and return
        // an opaque error instead of the plaintext length. Resize via CKR_BUFFER_TOO_SMALL
        // if the token needs more space (e.g. padding expansion on some mechanisms).
        NativeCULong decryptedDataLen = (NativeCULong)encryptedData.Length;
        byte[] decryptedData = new byte[encryptedData.Length];
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)encryptedData.Length, decryptedData, ref decryptedDataLen);

        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            decryptedData = new byte[(int)decryptedDataLen];
            rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)encryptedData.Length, decryptedData, ref decryptedDataLen);
        }

        Pkcs11Exception.ThrowIfError(rv, OpDecrypt);

        mechanism.AbsorbOutput(mechParams);

        if (decryptedData.Length != (int)decryptedDataLen)
            Array.Resize(ref decryptedData, (int)decryptedDataLen);

        return decryptedData;
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        Decrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDecryptInit);

        bool finalized = false;
        try
        {
            byte[] encryptedPart = new byte[bufferLength];
            byte[] part = new byte[bufferLength];
            NativeCULong partLen = (NativeCULong)(part.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
            {
                partLen = (NativeCULong)(part.Length);
                rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, OpDecryptUpdate);

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    part = new byte[(int)partLen];

                    rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                    Pkcs11Exception.ThrowIfError(rv, OpDecryptUpdate);
                }

                outputStream.Write(part, 0, (int)(partLen));
            }

            byte[]? lastPart = null;
            NativeCULong lastPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

            lastPart = new byte[(int)lastPartLen];
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
            finalized = true;

            mechanism.AbsorbOutput(mechParams);

            if (lastPartLen > (NativeCULong)0)
                outputStream.Write(lastPart, 0, (int)(lastPartLen));
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_DECRYPT, "Decrypt");
        }
    }

    /// <summary>
    /// One-shot AEAD decrypt via the PKCS#11 v3.0 message-based API
    /// (C_MessageDecryptInit + C_DecryptMessage + C_MessageDecryptFinal). The tag is
    /// supplied through <paramref name="messageParams"/> (constructed via the matching
    /// <c>ForDecrypt</c> factory) and verified by the token.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism.</param>
    /// <param name="keyHandle">Symmetric key handle.</param>
    /// <param name="messageParams">Per-message parameters carrying the nonce and tag.</param>
    /// <param name="associatedData">Optional AAD that was bound at encrypt time.</param>
    /// <param name="ciphertext">Ciphertext bytes (without the tag).</param>
    /// <returns>Plaintext.</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> on tag-verification failure.</exception>
    public byte[] MessageDecrypt(
        Mechanism mechanism,
        ObjectHandle keyHandle,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageDecrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        CKR rv = _pkcs11Library.C_MessageDecryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageDecryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            object paramsStruct = messageParams.BuildMarshalable(scope);
            int paramsSize = UnmanagedMemory.SizeOf(paramsStruct.GetType());
            IntPtr paramsPtr = scope.Allocate(paramsSize);
            UnmanagedMemory.Write(paramsPtr, paramsStruct);

            byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();
            byte[] ct = ciphertext.ToArray();

            NativeCULong ptLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DecryptMessage(
                _sessionId, paramsPtr, (NativeCULong)paramsSize,
                aad, (NativeCULong)aad.Length,
                ct, (NativeCULong)ct.Length,
                null!, ref ptLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DecryptMessage (length probe)");

            byte[] pt = new byte[(int)ptLen];
            rv = _pkcs11Library.C_DecryptMessage(
                _sessionId, paramsPtr, (NativeCULong)paramsSize,
                aad, (NativeCULong)aad.Length,
                ct, (NativeCULong)ct.Length,
                pt, ref ptLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptMessage);

            messageParams.AbsorbOutput(paramsStruct);

            if (pt.Length != (int)ptLen)
                Array.Resize(ref pt, (int)ptLen);

            return pt;
        }
        finally
        {
            CKR finalRv = _pkcs11Library.C_MessageDecryptFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                _logger.LogWarning("C_MessageDecryptFinal returned {Rv}", finalRv);
        }
    }

    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Sign");

        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpSignInit);

        byte[] signature = CallWithLengthProbe(
            (byte[]? buf, ref NativeCULong len) => _pkcs11Library.C_Sign(_sessionId, buffer, (NativeCULong)buffer.Length, buf, ref len),
            OpSign);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return signature;
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the given
    /// mechanism and key. Throws <see cref="InsecureOperationException"/> if
    /// <paramref name="mechanism"/> is insecure-by-default and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Verification mechanism.</param>
    /// <param name="keyHandle">Handle of the public/MAC key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        byte[] dataBuf = data.ToArray();
        byte[] sigBuf = signature.ToArray();
        Verify(mechanism, keyHandle, dataBuf, sigBuf, out isValid);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="data">Data that was signed</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, byte[] signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify1");

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpVerifyInit);

        rv = _pkcs11Library.C_Verify(_sessionId, data, (NativeCULong)(data.Length), signature, (NativeCULong)(signature.Length));
        isValid = IsVerified(rv, OpVerify);

        mechanism.AbsorbOutput(mechParams);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        Verify(mechanism, keyHandle, inputStream, signature, out isValid, 4096);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature, out bool isValid, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpVerifyInit);

        bool finalized = false;
        try
        {
            byte[] part = new byte[bufferLength];
            int bytesRead = 0;

            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part, (NativeCULong)(bytesRead));
                Pkcs11Exception.ThrowIfError(rv, OpVerifyUpdate);
            }

            rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
            // C_VerifyFinal always finalizes — whether the signature was valid, invalid, or
            // the call failed with any other CKR — the verify operation is consumed.
            finalized = true;
            isValid = IsVerified(rv, OpVerifyFinal);

            mechanism.AbsorbOutput(mechParams);
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_VERIFY, "Verify");
        }
    }

    /// <summary>
    /// Verifies signature of data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <returns>Data recovered from the signature</returns>
    public byte[] VerifyRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifyRecover");

        ArgumentNullException.ThrowIfNull(signature);

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_VerifyRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpVerifyRecoverInit);

        NativeCULong dataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), null, ref dataLen);
        Pkcs11Exception.ThrowIfError(rv, OpVerifyRecover);

        byte[] data = new byte[(int)dataLen];
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), data, ref dataLen);
        isValid = IsVerified(rv, OpVerifyRecover);

        mechanism.AbsorbOutput(mechParams);

        if (data.Length != (int)(dataLen))
            Array.Resize(ref data, (int)(dataLen));

        return data;
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="signature">Signature</param>
    /// <param name="decryptedData">Decrypted data</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, byte[] data, byte[] signature, out byte[] decryptedData, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(verificationMechanism);
        GuardMechanism(decryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify1");

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputMemoryStream, outputMemorySteam, signature, out isValid);
        decryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(verificationMechanism);
        GuardMechanism(decryptionMechanism);

        ThrowIfOneDescriptorDrivesBothHalves(verificationMechanism, decryptionMechanism, nameof(decryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputStream, outputStream, signature, out isValid, 4096);
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature, out bool isValid, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(verificationMechanism);
        GuardMechanism(decryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        // Both mechanisms marshal into the same scope: the two operations run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckVerificationMechanism = verificationMechanism.Marshal(scope, out object? verifyParams);

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckVerificationMechanism, (NativeCULong)(verificationKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpVerifyInit);

        CK_MECHANISM ckDecryptionMechanism = decryptionMechanism.Marshal(scope, out object? decryptParams);

        rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(decryptionKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDecryptInit);

        byte[] encryptedPart = new byte[bufferLength];
        byte[] part = new byte[bufferLength];
        NativeCULong partLen = (NativeCULong)(part.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
        {
            partLen = (NativeCULong)(part.Length);
            rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
            if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, OpDecryptVerifyUpdate);

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                Pkcs11Exception.ThrowIfError(rv, OpDecryptVerifyUpdate);
            }

            outputStream.Write(part, 0, (int)(partLen));
        }

        byte[]? lastPart = null;
        NativeCULong lastPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        lastPart = new byte[(int)lastPartLen];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        if (lastPartLen > (NativeCULong)0)
            outputStream.Write(lastPart, 0, (int)(lastPartLen));

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
        isValid = IsVerified(rv, OpVerifyFinal);

        verificationMechanism.AbsorbOutput(verifyParams);
        decryptionMechanism.AbsorbOutput(decryptParams);
    }

    private const string ValueMustBePositive = "Value has to be positive number";

    /// <summary>
    /// Digests the value of a secret key
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="keyHandle">Handle of the secret key to be digested</param>
    /// <returns>Digest</returns>
    public byte[] DigestKey(Mechanism mechanism, ObjectHandle keyHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, OpDigestInit);

        rv = _pkcs11Library.C_DigestKey(_sessionId, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDigestKey);

        NativeCULong digestLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

        byte[] digest = new byte[(int)digestLen];
        rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

        mechanism.AbsorbOutput(mechParams);

        if (digest.Length != (int)(digestLen))
            Array.Resize(ref digest, (int)(digestLen));

        return digest;
    }

    /// <summary>
    /// Computes a digest over <paramref name="data"/> using the given mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list (raw MD5 / SHA-1) and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The digest mechanism (typically <see cref="CKM.CKM_SHA256"/> or stronger).</param>
    /// <param name="data">Data to digest.</param>
    /// <returns>Digest bytes (length depends on the mechanism — 32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Digest(mechanism, buffer);
    }

    /// <summary>
    /// Digests single-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="data">Data to be digested</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, byte[] data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest1");

        ArgumentNullException.ThrowIfNull(data);

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, OpDigestInit);

        byte[] digest = CallWithLengthProbe(
            (byte[]? buf, ref NativeCULong len) => _pkcs11Library.C_Digest(_sessionId, data, (NativeCULong)(data.Length), buf, ref len),
            OpDigest);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return digest;
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        return Digest(mechanism, inputStream, 4096);
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, OpDigestInit);

        bool finalized = false;
        try
        {
            byte[] part = new byte[bufferLength];
            int bytesRead = 0;

            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                rv = _pkcs11Library.C_DigestUpdate(_sessionId, part, (NativeCULong)(bytesRead));
                Pkcs11Exception.ThrowIfError(rv, OpDigestUpdate);
            }

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);
            finalized = true;

            mechanism.AbsorbOutput(mechParams);

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_DIGEST, "Digest");
        }
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] encryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(encryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt1");

        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        digest = DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
        encryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(encryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(encryptionMechanism);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, encryptionMechanism, nameof(encryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        // Both mechanisms marshal into the same scope: digest and encrypt run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckDigestingMechanism = digestingMechanism.Marshal(scope, out object? digestParams);

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, OpDigestInit);

        bool encryptInited = false;
        bool encryptFinalized = false;
        bool digestFinalized = false;
        try
        {
            CK_MECHANISM ckEncryptionMechanism = encryptionMechanism.Marshal(scope, out object? encryptParams);

            rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckEncryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
            Pkcs11Exception.ThrowIfError(rv, OpEncryptInit);
            encryptInited = true;

            byte[] part = new byte[bufferLength];
            byte[] encryptedPart = new byte[bufferLength];
            NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                encryptedPartLen = (NativeCULong)(encryptedPart.Length);
                rv = _pkcs11Library.C_DigestEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, OpDigestEncryptUpdate);

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    encryptedPart = new byte[(int)encryptedPartLen];

                    rv = _pkcs11Library.C_DigestEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                    Pkcs11Exception.ThrowIfError(rv, OpDigestEncryptUpdate);
                }

                outputStream.Write(encryptedPart, 0, (int)(encryptedPartLen));
            }

            byte[]? lastEncryptedPart = null;
            NativeCULong lastEncryptedPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);

            lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);
            encryptFinalized = true;

            if (lastEncryptedPartLen > (NativeCULong)0)
                outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);
            digestFinalized = true;

            digestingMechanism.AbsorbOutput(digestParams);
            encryptionMechanism.AbsorbOutput(encryptParams);

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            // Cancel whichever sub-operations are still live. Encrypt-init may not have
            // succeeded; both are independent active operations on the session per v3.0+.
            NativeCULong cancelFlags = (NativeCULong)0;
            if (!digestFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DIGEST);
            if (encryptInited && !encryptFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_ENCRYPT);
            if ((ulong)cancelFlags != 0)
                TryCancelOperation(cancelFlags, "DigestEncrypt");
        }
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="decryptedData">Decrypted data</param>
    public void DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] decryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(decryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest1");

        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        digest = DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
        decryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(decryptionMechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism(digestingMechanism);
        GuardMechanism(decryptionMechanism);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, decryptionMechanism, nameof(decryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        // Both mechanisms marshal into the same scope: decrypt and digest run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckDigestingMechanism = digestingMechanism.Marshal(scope, out object? digestParams);

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, OpDigestInit);

        bool decryptInited = false;
        bool decryptFinalized = false;
        bool digestFinalized = false;
        try
        {
            CK_MECHANISM ckDecryptionMechanism = decryptionMechanism.Marshal(scope, out object? decryptParams);

            rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
            Pkcs11Exception.ThrowIfError(rv, OpDecryptInit);
            decryptInited = true;

            byte[] encryptedPart = new byte[bufferLength];
            byte[] part = new byte[bufferLength];
            NativeCULong partLen = (NativeCULong)(part.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
            {
                partLen = (NativeCULong)(part.Length);
                rv = _pkcs11Library.C_DecryptDigestUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, OpDecryptDigestUpdate);

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    part = new byte[(int)partLen];

                    rv = _pkcs11Library.C_DecryptDigestUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                    Pkcs11Exception.ThrowIfError(rv, OpDecryptDigestUpdate);
                }

                outputStream.Write(part, 0, (int)(partLen));
            }

            byte[]? lastPart = null;
            NativeCULong lastPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

            lastPart = new byte[(int)lastPartLen];
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
            decryptFinalized = true;

            if (lastPartLen > (NativeCULong)0)
                outputStream.Write(lastPart, 0, (int)(lastPartLen));

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);
            digestFinalized = true;

            digestingMechanism.AbsorbOutput(digestParams);
            decryptionMechanism.AbsorbOutput(decryptParams);

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            NativeCULong cancelFlags = (NativeCULong)0;
            if (!digestFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DIGEST);
            if (decryptInited && !decryptFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DECRYPT);
            if ((ulong)cancelFlags != 0)
                TryCancelOperation(cancelFlags, "DecryptDigest");
        }
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object. Secure defaults
    /// (<c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c>) are applied to the result template;
    /// an explicit insecure value requires <see cref="AllowInsecure"/>.
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DeriveKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        // Deriving produces a new key object on the token. Apply the same secure defaults as UnwrapKey
        // (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the caller omitted them); an explicit insecure
        // value requires AllowInsecure (throws otherwise). See BuildSecureKeyDefaults. Trusted internal
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults, out NativeCULong templateLen);

        NativeCULong derivedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, ref ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, templateLen, ref derivedKey);
        Pkcs11Exception.ThrowIfError(rv, OpDeriveKey);

        // SP800-108 sibling-key handles live in scope-owned slots the token wrote into; copy them
        // out before `scope` is disposed.
        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)derivedKey);
    }

    /// <summary>
    /// Seeds the token's random number generator with caller-supplied entropy. Useful when
    /// the host has access to high-quality entropy (e.g., another RNG) that the caller wants
    /// to mix into the token's internal state. Most callers should rely solely on the token's
    /// internal RNG and call <see cref="GenerateRandom(int)"/> directly.
    /// </summary>
    /// <param name="seed">Entropy bytes to mix into the token RNG.</param>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        using var _ = AcquireExclusive();

        // The interop signature takes byte[], so the caller's entropy has to be copied. Zero the
        // copy on the way out: seed material is as sensitive as the keys it will help produce.
        byte[] buffer = seed.ToArray();
        try
        {
            SeedRandom(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "SeedRandom");

        ArgumentNullException.ThrowIfNull(seed);

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed, (NativeCULong)(seed.Length));
        Pkcs11Exception.ThrowIfError(rv, OpSeedRandom);
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with random bytes from the token's RNG and
    /// returns the number of bytes written.
    /// </summary>
    /// <param name="destination">Buffer to fill. The full length of <paramref name="destination"/> is filled.</param>
    /// <returns>Number of bytes written (equal to <paramref name="destination"/>.Length).</returns>
    public int GenerateRandom(Span<byte> destination)
    {
        using var _ = AcquireExclusive();
        if (destination.IsEmpty) return 0;

        // The interop signature takes byte[], so the token's output lands in a transient before it
        // reaches the caller's span. Zero it: this is freshly generated key material, and leaving a
        // second copy on the GC heap defeats the point of the caller passing a span it controls.
        byte[] random = GenerateRandom(destination.Length);
        try
        {
            random.CopyTo(destination);
            return destination.Length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="length">Length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>Generated random or pseudo-random data</returns>
    public byte[] GenerateRandom(int length)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateRandom");

        if (length < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(length));

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData, (NativeCULong)(length));
        Pkcs11Exception.ThrowIfError(rv, OpGenerateRandom);

        return randomData;
    }

    /// <summary>
    /// True when the loaded library exposes the PKCS#11 v3.2 surface (encapsulate /
    /// decapsulate / authenticated wrap / signature-only verify). On v2.40 and v3.0/v3.1
    /// libraries this is false and the corresponding methods throw
    /// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>.
    /// </summary>
    public bool SupportsV32Api
        => _pkcs11Library is not null && _pkcs11Library.IsV32ApiSupported;

    // === ML-KEM: encapsulate / decapsulate =================================

    /// <summary>
    /// Encapsulates a fresh shared-secret key against <paramref name="encapsulatingPublicKey"/>
    /// (typically an ML-KEM public key). Returns the ciphertext to be sent to the holder
    /// of the matching private key, plus a handle to the freshly-derived shared-secret
    /// key on the token (PKCS#11 v3.2 §5.18.10).
    /// </summary>
    /// <param name="mechanism">Encapsulation mechanism (e.g. <see cref="CKM.CKM_ML_KEM"/>).</param>
    /// <param name="encapsulatingPublicKey">Handle of the public key to encapsulate against.</param>
    /// <param name="sharedKeyTemplate">Template applied to the derived shared-secret key.</param>
    /// <param name="expectedCiphertextLen">
    /// When &gt; 0, the exact ciphertext length is already known (e.g. fixed by the ML-KEM parameter
    /// set), so a single <c>C_EncapsulateKey</c> call is made with a pre-sized buffer. This skips the
    /// NULL-buffer length probe, which some tokens (SoftHSM) do not honour for <c>C_EncapsulateKey</c>:
    /// they leave <c>*pulCipherTextLen</c> untouched on a NULL buffer yet still run a full,
    /// side-effectful encapsulation per call, so a probe would both fail to report the size and leak an
    /// extra shared-secret object. When 0, the two-call probe is used (caller does not know the size).
    /// </param>
    /// <returns>Tuple of (ciphertext, sharedKeyHandle).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public (byte[] Ciphertext, ObjectHandle SharedKey) EncapsulateKey(
        Mechanism mechanism,
        ObjectHandle encapsulatingPublicKey,
        List<ObjectAttribute> sharedKeyTemplate,
        int expectedCiphertextLen = 0)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "EncapsulateKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        // The encapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires AllowInsecure. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong ctLen = (NativeCULong)0;
        NativeCULong sharedHandle = CK.CK_INVALID_HANDLE;
        CKR rv;
        byte[] ct;

        if (expectedCiphertextLen > 0)
        {
            // Single-call: the exact ciphertext size is known, so hand the token a correctly-sized
            // buffer and let it fill it in one shot. This is the spec-correct path on every token
            // and the only correct path on SoftHSM, whose C_EncapsulateKey ignores a NULL buffer
            // (no length probe) and performs a side-effectful encapsulation on each call.
            ct = new byte[expectedCiphertextLen];
            ctLen = (NativeCULong)expectedCiphertextLen;
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template, (NativeCULong)template.Length,
                ct, ref ctLen, ref sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }
        else
        {
            // Two-call: query size first, then real encaps (size unknown to the caller).
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template, (NativeCULong)template.Length,
                null!, ref ctLen, ref sharedHandle);
            // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome: the token populated
            // ctLen even though the (null) output buffer was inadequate (PKCS#11 v3.2 §5.2).
            // Only a genuine error aborts the probe.
            if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_EncapsulateKey (length probe)");

            ct = new byte[(int)ctLen];
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template, (NativeCULong)template.Length,
                ct, ref ctLen, ref sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }

        mechanism.AbsorbOutput(mechParams);

        if (ct.Length != (int)ctLen)
            Array.Resize(ref ct, (int)ctLen);

        return (ct, new ObjectHandle((ulong)sharedHandle));
    }

    /// <summary>
    /// Decapsulates the shared-secret key from <paramref name="ciphertext"/> using
    /// <paramref name="decapsulatingPrivateKey"/> (typically an ML-KEM private key)
    /// (PKCS#11 v3.2 §5.18.11).
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public ObjectHandle DecapsulateKey(
        Mechanism mechanism,
        ObjectHandle decapsulatingPrivateKey,
        ReadOnlySpan<byte> ciphertext,
        List<ObjectAttribute> sharedKeyTemplate)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecapsulateKey");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);

        // The decapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires AllowInsecure. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        byte[] ct = ciphertext.ToArray();
        NativeCULong sharedHandle = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DecapsulateKey(
            _sessionId, ref ckMechanism, (NativeCULong)decapsulatingPrivateKey.ObjectId,
            template, (NativeCULong)template.Length,
            ct, (NativeCULong)ct.Length, ref sharedHandle);
        Pkcs11Exception.ThrowIfError(rv, OpDecapsulateKey);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)sharedHandle);
    }

    // === Authenticated wrap ================================================

    /// <summary>
    /// Wraps <paramref name="keyToWrap"/> with <paramref name="wrappingKey"/>,
    /// binding the wrap to <paramref name="associatedData"/>. The same AAD must be
    /// supplied at unwrap or unwrap fails (PKCS#11 v3.2 §5.18.12).
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public byte[] WrapKeyAuthenticated(
        Mechanism mechanism,
        ObjectHandle wrappingKey,
        ObjectHandle keyToWrap,
        ReadOnlySpan<byte> associatedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKeyAuthenticated");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();

        NativeCULong wrappedLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            aad, (NativeCULong)aad.Length, null!, ref wrappedLen);
        // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome (PKCS#11 v3.2 §5.2):
        // the token populated wrappedLen despite the (null) output buffer. Only a genuine
        // error aborts the probe.
        if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
            Pkcs11Exception.ThrowIfError(rv, "C_WrapKeyAuthenticated (length probe)");

        byte[] wrapped = new byte[(int)wrappedLen];
        rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            aad, (NativeCULong)aad.Length, wrapped, ref wrappedLen);
        Pkcs11Exception.ThrowIfError(rv, OpWrapKeyAuthenticated);

        mechanism.AbsorbOutput(mechParams);

        if (wrapped.Length != (int)wrappedLen)
            Array.Resize(ref wrapped, (int)wrappedLen);

        return wrapped;
    }

    /// <summary>
    /// Unwraps <paramref name="wrappedKey"/> using <paramref name="unwrappingKey"/>,
    /// verifying that the wrap was authenticated against <paramref name="associatedData"/>.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2; <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> when the AAD doesn't match.</exception>
    public ObjectHandle UnwrapKeyAuthenticated(
        Mechanism mechanism,
        ObjectHandle unwrappingKey,
        ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<byte> associatedData,
        List<ObjectAttribute> unwrappedKeyTemplate)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappedKeyTemplate);
        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKeyAuthenticated");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        byte[] wrapped = wrappedKey.ToArray();
        byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();

        // Authenticated unwrap lands a new key object on the token, exactly as UnwrapKey does. Apply the
        // same secure defaults (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires AllowInsecure. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(unwrappedKeyTemplate);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[unwrappedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < unwrappedKeyTemplate.Count; i++)
            template[idx++] = unwrappedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong newKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)unwrappingKey.ObjectId,
            wrapped, (NativeCULong)wrapped.Length,
            template, (NativeCULong)template.Length,
            aad, (NativeCULong)aad.Length, ref newKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKeyAuthenticated);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)newKey);
    }

    // === Signature-only verify (init binds the signature, data feeds in) ====

    /// <summary>
    /// One-shot streaming-friendly signature-only verify (PKCS#11 v3.2 §5.16.10–11).
    /// Unlike <c>Verify</c>, the signature is bound at init time so the data can be
    /// fed as a stream. This is a one-shot wrapper that supplies all data at once.
    /// </summary>
    /// <returns><c>true</c> if the signature verifies; <c>false</c> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    /// <exception cref="Pkcs11Exception">Any other PKCS#11 error.</exception>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        byte[] sig = signature.ToArray();
        byte[] dataBuf = data.ToArray();

        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            sig, (NativeCULong)sig.Length);
        Pkcs11Exception.ThrowIfError(rv, OpVerifySignatureInit);

        rv = _pkcs11Library.C_VerifySignature(_sessionId, dataBuf, (NativeCULong)dataBuf.Length);
        bool verified = IsVerified(rv, OpVerifySignature);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return verified;
    }

    /// <summary>
    /// Streaming signature-only verify: binds <paramref name="signature"/> at init,
    /// then feeds <paramref name="inputStream"/> through C_VerifySignatureUpdate and
    /// finalizes via C_VerifySignatureFinal.
    /// </summary>
    /// <returns><c>true</c> if the signature verifies; <c>false</c> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        Stream inputStream,
        int bufferLength = 4096)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(inputStream);
        if (bufferLength < 1)
            throw new ArgumentException("Value has to be a positive number.", nameof(bufferLength));
        GuardMechanism(mechanism);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature(stream)");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out object? mechParams);
        byte[] sig = signature.ToArray();

        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            sig, (NativeCULong)sig.Length);
        Pkcs11Exception.ThrowIfError(rv, OpVerifySignatureInit);

        byte[] buffer = new byte[bufferLength];
        int read;
        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifySignatureUpdate(_sessionId, buffer, (NativeCULong)read);
            Pkcs11Exception.ThrowIfError(rv, OpVerifySignatureUpdate);
        }

        rv = _pkcs11Library.C_VerifySignatureFinal(_sessionId);
        bool verified = IsVerified(rv, OpVerifySignatureFinal);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return verified;
    }

    // === Validation flags ==================================================

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type
    /// (PKCS#11 v3.2 §5.6.10). <paramref name="validationType"/> is typically
    /// <see cref="CksValidationFlagsType.CKS_LAST_VALIDATION_OK"/> to query whether the most recent
    /// operation completed within the active validation profile.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public ulong GetSessionValidationFlags(CksValidationFlagsType validationType)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionGetValidationFlags(_logger, (ulong)_sessionId, (ulong)validationType);

        NativeCULong flags = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetSessionValidationFlags(_sessionId, (NativeCULong)(ulong)validationType, ref flags);
        Pkcs11Exception.ThrowIfError(rv, OpGetSessionValidationFlags);

        return (ulong)flags;
    }
}
