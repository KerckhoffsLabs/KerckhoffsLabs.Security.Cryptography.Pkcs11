using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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
    private readonly ILogger _logger;

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
    private Pkcs11SessionHandle _sessionHandle;

    /// <summary>
    /// Compatibility shim — returns the underlying session ID, or <see cref="CK.CK_INVALID_HANDLE"/>
    /// if the session is not yet open or has been closed. Read-only; assignments go through
    /// <see cref="_sessionHandle"/>.
    /// </summary>
    private NativeCULong _sessionId => _sessionHandle is null ? (NativeCULong)CK.CK_INVALID_HANDLE : _sessionHandle.SessionId;

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

    /// <summary>
    /// Disposable token returned by <see cref="AcquireExclusive"/>. Holds the busy lock and a reference
    /// on the session handle, and releases both on dispose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reference is what keeps the session open for a whole operation, from <c>C_*Init</c> to the
    /// last call: closing the handle elsewhere (<c>Pkcs11Library.Dispose</c> closes every tracked
    /// session) only marks it closed, and its <c>C_CloseSession</c> waits until this lease lets go.
    /// </para>
    /// <para>
    /// Implemented as <c>internal sealed class</c> (not <c>ref struct</c>) so the test suite can
    /// invoke <see cref="AcquireExclusive"/> via <c>[InternalsVisibleTo]</c> and hold the lease
    /// across a thread boundary. The one extra heap allocation per public method call is
    /// negligible against the cost of crossing the P/Invoke boundary that follows.
    /// </para>
    /// </remarks>
    internal sealed class ExclusiveLease : IDisposable
    {
        private readonly object _lock;
        private Pkcs11SessionHandle? _handle;
        private bool _released;

        internal ExclusiveLease(object lockObj)
        {
            _lock = lockObj;
            _released = false;
        }

        /// <summary>Takes a reference on <paramref name="handle"/>; throws <see cref="ObjectDisposedException"/> if it is already closed.</summary>
        internal void Hold(Pkcs11SessionHandle handle)
        {
            bool added = false;
            handle.DangerousAddRef(ref added);
            if (added)
                _handle = handle;
        }

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            // The reference first: a deferred C_CloseSession then runs while this thread still holds
            // the lock, so no other operation can start on the session it is closing.
            _handle?.DangerousRelease();
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

        var lease = new ExclusiveLease(_busyLock);
        try
        {
            // Under the lock, deliberately: checking before it would race Dispose, which sets the
            // flag while holding it. Every operation needs this, so it lives here rather than being
            // restated at each call site, where the omission of one line would be invisible.
            ObjectDisposedException.ThrowIf(_disposed, this);
            lease.Hold(_sessionHandle);
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
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

    // NOTE: no CloseWhenDisposed flag. It used to gate whether Dispose released the session handle,
    // but it could not deliver what its name promised: Pkcs11SessionHandle is a SafeHandle with a
    // critical finalizer, so a session held back from closing still got C_CloseSession once the
    // handle became unreachable — just nondeterministically, and in principle after C_Finalize.
    // Honouring it properly would mean detaching the handle (SetHandleAsInvalid plus untracking it),
    // which leaks a live session on the token by design. Nothing in the library or tests ever set
    // it, so there was no behaviour to preserve — only a misleading contract to remove.

    /// <summary>The policy the session was opened under. Never changes.</summary>
    private readonly ICryptoPolicy _basePolicy;

    /// <summary>
    /// The policy currently enforced — the policy of the most recent open override lease, or
    /// <see cref="_basePolicy"/> when none is open. Written under <see cref="_policyLock"/>, but read
    /// outside it by <see cref="Enforce(PolicyRequest)"/>, so it is <c>volatile</c>.
    /// </summary>
    private volatile ICryptoPolicy _effectivePolicy;

    /// <summary>
    /// Override leases still open, oldest first. Guarded by <see cref="_policyLock"/>.
    /// </summary>
    /// <remarks>
    /// A list rather than a saved "previous policy" per lease: a lease disposed out of order must
    /// only withdraw itself. Restoring whatever it saw on entry would let an outer permissive lease
    /// be re-instated by the disposal of a stricter inner one after the outer lease was already
    /// closed.
    /// </remarks>
    private readonly List<PolicyLease> _policyLeases = [];

    /// <summary>Guards <see cref="_policyLeases"/> and writes to <see cref="_effectivePolicy"/>.</summary>
    private readonly Lock _policyLock = new();

    /// <summary>The policy currently enforced on this session.</summary>
    internal ICryptoPolicy Policy
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _effectivePolicy;
        }
    }

    /// <summary>
    /// Evaluates <paramref name="request"/> under the effective policy; on denial logs a warning and
    /// throws. The only place a policy verdict becomes an exception.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the request.</exception>
    internal void Enforce(PolicyRequest request)
    {
        ICryptoPolicy policy = _effectivePolicy;
        PolicyDecision decision = policy.Evaluate(request);
        if (decision.IsAllowed)
            return;

        Log.PolicyDenied(_logger, (ulong)_sessionId, policy.Name, request.Describe());
        throw new CryptoPolicyViolationException(policy.Name, request, decision.Reason!);
    }

    /// <summary>Evaluates without throwing or logging.</summary>
    internal bool IsPermitted(PolicyRequest request)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _effectivePolicy.Evaluate(request).IsAllowed;
    }

    private void Enforce(Mechanism mechanism, CryptoOperation operation)
    {
        Enforce(new MechanismUseRequest(mechanism, operation));

        // The KDF an ECDH derivation or KEM applies to the shared secret is judged here, on every call
        // carrying CK_ECDH1_DERIVE_PARAMS, whichever public entry point it came through.
        if (mechanism.Parameters is CkmEcdh1DeriveParams ecdh)
            Enforce(new KeyAgreementKdfRequest(mechanism.Type, ecdh.Kdf));
    }

    /// <summary>
    /// Enforces the policy for a message-based operation. Its per-message parameters, which carry an
    /// AEAD's tag length, never reach the mechanism <c>C_Message[En|De]cryptInit</c> receives, so a
    /// mechanism without parameters of its own is judged with them: a parameter rule then sees the
    /// call exactly as the single-part API would show it.
    /// </summary>
    private void EnforceMessage(Mechanism mechanism, MechanismParameters messageParams, CryptoOperation operation) =>
        Enforce(
            mechanism.Parameters is null && !mechanism.HasRawParameter
                ? new Mechanism(mechanism.Type, messageParams)
                : mechanism,
            operation);

    /// <summary>
    /// Replaces the effective policy until the returned lease is disposed. Logged. Refused when the
    /// session's base policy does not allow overrides.
    /// </summary>
    /// <remarks>
    /// Leases form a stack: the most recent open lease decides the effective policy. Disposing a
    /// lease withdraws only that lease, wherever it sits, and the effective policy becomes that of
    /// the most recent lease still open, or the base policy when none is — so disposing leases out
    /// of order never re-instates a policy whose lease is already closed.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The base policy's <see cref="ICryptoPolicy.AllowsOverride"/> is false.</exception>
    internal IDisposable UsePolicy(ICryptoPolicy policy)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(policy);
        if (!_basePolicy.AllowsOverride)
            throw new InvalidOperationException(
                $"This session was opened under the {_basePolicy.Name} policy, which does not allow overrides.");

        var lease = new PolicyLease(this, policy);
        lock (_policyLock)
        {
            Log.PolicyOverridden(_logger, (ulong)_sessionId, _effectivePolicy.Name, policy.Name);
            _policyLeases.Add(lease);
            _effectivePolicy = policy;
        }
        return lease;
    }

    /// <summary>
    /// Withdraws <paramref name="lease"/> from the lease stack and recomputes the effective policy.
    /// A no-op once the session is disposed.
    /// </summary>
    private void ReleasePolicyLease(PolicyLease lease)
    {
        lock (_policyLock)
        {
            if (_disposed)
                return;

            _policyLeases.Remove(lease);
            ICryptoPolicy previous = _effectivePolicy;
            ICryptoPolicy restored = _policyLeases.Count > 0 ? _policyLeases[^1].Policy : _basePolicy;
            if (ReferenceEquals(previous, restored))
                return;

            _effectivePolicy = restored;
            Log.PolicyRestored(_logger, (ulong)_sessionId, previous.Name, restored.Name);
        }
    }

    /// <summary>An open policy override. Disposing it withdraws it from the session's lease stack.</summary>
    private sealed class PolicyLease(Pkcs11Session session, ICryptoPolicy policy) : IDisposable
    {
        private int _released;

        /// <summary>The policy this lease puts in force.</summary>
        public ICryptoPolicy Policy { get; } = policy;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0) return;
            session.ReleasePolicyLease(this);
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

        if (_supportedMechanisms is null)
        {
            CK_SESSION_INFO info = new();
            CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref info);
            if (rv != CKR.CKR_OK) return false;

            rv = _pkcs11Library.C_GetMechanismList(info.SlotId, [], out NativeCULong count);
            if (rv != CKR.CKR_OK || count.Value == 0)
            {
                _supportedMechanisms = [];
                return false;
            }

            CKM[] list = new CKM[(int)count.Value];
            rv = _pkcs11Library.C_GetMechanismList(info.SlotId, list, out count);
            // Only the first `count` entries were returned; the rest still hold default(CKM), which is a
            // real mechanism (CKM_RSA_PKCS_KEY_PAIR_GEN) the module never reported.
            _supportedMechanisms = rv == CKR.CKR_OK ? [.. list.AsSpan(0, (int)Math.Min(count.Value, (ulong)list.Length))] : [];
        }
        return _supportedMechanisms.Contains(mechanism);
    }

    /// <summary>
    /// Wraps an already-open PKCS#11 session handle.
    /// </summary>
    /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    /// <param name="loggerFactory">
    /// Logger factory inherited from the owning <see cref="Pkcs11Slot"/>/<see cref="Pkcs11Library"/>;
    /// <see langword="null"/> for no logging.
    /// </param>
    /// <param name="policy">
    /// The policy to enforce on this session; <see langword="null"/> means <see cref="CryptoPolicy.SecureOnly"/>.
    /// </param>
    internal Pkcs11Session(ILowLevelPkcs11Library pkcs11Library, ulong sessionId, ILoggerFactory? loggerFactory = null, ICryptoPolicy? policy = null)
        : this(pkcs11Library, OwnSession(pkcs11Library, sessionId), loggerFactory, policy)
    {
    }

    /// <summary>
    /// Takes ownership of an open session's <paramref name="sessionHandle"/>: if construction throws, the
    /// handle is disposed and the session closed, so it can never be left open with no owner.
    /// </summary>
    internal Pkcs11Session(ILowLevelPkcs11Library pkcs11Library, Pkcs11SessionHandle sessionHandle, ILoggerFactory? loggerFactory = null, ICryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(sessionHandle);
        _sessionHandle = sessionHandle;
        try
        {
            if (sessionHandle.IsInvalid)
                throw new ArgumentException("Invalid handle specified", nameof(sessionHandle));

            // Both run consumer code (the factory, the logger), which may throw.
            _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<Pkcs11Session>();
            Log.SessionTrace(_logger, (ulong)sessionHandle.SessionId, "ctor");

            _basePolicy = policy ?? CryptoPolicy.SecureOnly;
            _effectivePolicy = _basePolicy;
            _pkcs11Library = pkcs11Library;
        }
        catch
        {
            sessionHandle.Dispose();
            throw;
        }
    }

    private static Pkcs11SessionHandle OwnSession(ILowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        ArgumentNullException.ThrowIfNull(pkcs11Library);
        if (sessionId == CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", nameof(sessionId));
        return new Pkcs11SessionHandle(pkcs11Library, (NativeCULong)sessionId);
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

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Logging as {UserType} into session {SessionId}", Pkcs11LogUtils.ToString(userType), _sessionId);

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

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation(
                "Logging as {UserType} into session {SessionId} via protected authentication path",
                Pkcs11LogUtils.ToString(userType), _sessionId);

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

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation(
                "Logging in as {UserType} (username supplied) on session {SessionId}",
                Pkcs11LogUtils.ToString(userType), _sessionId);

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

        Log.SessionCancelOperations(_logger, (ulong)_sessionId, flags);

        CKR rv = _pkcs11Library.C_SessionCancel(_sessionId, (NativeCULong)flags);
        Pkcs11Exception.ThrowIfError(rv, OpSessionCancel);
    }

    /// <summary>
    /// Operations (<c>CKF_SIGN</c>, <c>CKF_DECRYPT</c>, ...) begun on this session and not yet ended. Kept
    /// here rather than in <see cref="OperationScope"/>: a <c>using</c> struct local is read-only, so the
    /// scope could not record anything in itself. The session lease makes this field exclusive.
    /// </summary>
    private ulong _operationsInProgress;

    /// <summary>
    /// Operations this session abandoned after an error without being able to cancel them (no
    /// <c>C_SessionCancel</c> before v3.0): the module may still hold them active. Cleared by the next
    /// successful <c>C_*Init</c> of the same kind.
    /// </summary>
    private ulong _operationsAbandoned;

    /// <summary>
    /// Ends whatever operations it saw begin, on any exit: an exception between <c>C_*Init</c> and the
    /// call that finishes the operation would otherwise leave it active, and every later
    /// <c>C_*Init</c> of that kind on the session would fail with <c>CKR_OPERATION_ACTIVE</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Usage: declare it after the <see cref="MechanismParameterScope"/>, so it is disposed first and the
    /// cancel runs while the mechanism's parameter block is still allocated. Report each
    /// <c>C_*Init</c> through <see cref="Begin"/>, and call <see cref="Completed"/> once the call that
    /// finishes the operation has returned. A return code other than <c>CKR_OK</c> or
    /// <c>CKR_BUFFER_TOO_SMALL</c> already ends an operation (PKCS#11 v3.2 §5.2), so the cancel only
    /// matters when this library's own code throws between two calls; one that finds nothing to cancel
    /// is expected.
    /// </para>
    /// <para>
    /// The cancel is <c>C_SessionCancel</c> (v3.0+). On a module without it the operation may stay
    /// active, so the session remembers it, and the next <c>C_*Init</c> of that kind that fails with
    /// <c>CKR_OPERATION_ACTIVE</c> says why instead of leaving the caller to guess.
    /// </para>
    /// </remarks>
    private readonly ref struct OperationScope : IDisposable
    {
        private readonly Pkcs11Session _session;
        private readonly string _name;

        // What was in progress before this scope: an operation begun by a caller re-entering on this
        // thread is that caller's to end.
        private readonly ulong _outer;

        internal OperationScope(Pkcs11Session session, string name)
        {
            _session = session;
            _name = name;
            _outer = session._operationsInProgress;
        }

        /// <summary>Checks a <c>C_*Init</c>'s return; on success, <paramref name="operation"/> is in progress.</summary>
        public void Begin(ulong operation, CKR rv, string initFunction)
        {
            _session.ThrowIfInitFailed(operation, rv, initFunction);
            _session._operationsInProgress |= operation;
        }

        /// <summary>Records that the call finishing <paramref name="operation"/> has returned.</summary>
        public void End(ulong operation) => _session._operationsInProgress &= ~operation;

        /// <summary>Records that every operation this scope began has ended.</summary>
        public void Completed() => _session._operationsInProgress = _outer;

        public void Dispose()
        {
            ulong unfinished = _session._operationsInProgress & ~_outer;
            _session._operationsInProgress = _outer;
            if (unfinished != 0)
                _session.CancelAbandoned(unfinished, _name);
        }
    }

    private OperationScope BeginOperation(string name) => new(this, name);

    private void ThrowIfInitFailed(ulong operation, CKR rv, string initFunction)
    {
        if (rv == CKR.CKR_OK)
        {
            _operationsAbandoned &= ~operation;
            return;
        }
        if (rv == CKR.CKR_OPERATION_ACTIVE && (_operationsAbandoned & operation) != 0)
        {
            throw new Pkcs11UnclassifiedException(rv, initFunction,
                "An earlier operation of this kind on this session failed partway through, and this module " +
                "cannot cancel it (it has no C_SessionCancel), so it is still active. Open a new session.");
        }
        Pkcs11Exception.ThrowIfError(rv, initFunction);
    }

    /// <summary>
    /// Cancels operations abandoned on an exception. Never throws: it runs while that exception unwinds,
    /// and must not replace it.
    /// </summary>
    private void CancelAbandoned(ulong operations, string operationName)
    {
        CKR rv;
        try
        {
            rv = _pkcs11Library.C_SessionCancel(_sessionId, (NativeCULong)operations);
        }
        catch (ObjectDisposedException)
        {
            return; // the library is gone, and the session with it
        }

        switch (rv)
        {
            case CKR.CKR_OK:
            case CKR.CKR_OPERATION_NOT_INITIALIZED: // the error that started the unwind had already ended it
                return;
            case CKR.CKR_FUNCTION_NOT_SUPPORTED:
                _operationsAbandoned |= operations;
                return;
            default:
                _operationsAbandoned |= operations;
                _logger.LogWarning(
                    "Session({SessionId})::{Operation}: C_SessionCancel returned {Rv} during cleanup",
                    _sessionId, operationName, rv);
                return;
        }
    }

    /// <summary>
    /// The logout an owning <see cref="Pkcs11Workspace"/> issues just before disposing this session.
    /// Waits for the busy lock instead of going through <see cref="AcquireExclusive"/>, for the
    /// reason <see cref="Dispose(bool)"/> does: it runs from a disposal, where throwing on
    /// cross-thread contention would leave the session open and replace any exception a
    /// surrounding <c>using</c> is unwinding. A session that is already disposed is left alone.
    /// </summary>
    /// <exception cref="Pkcs11Exception">The token rejected the logout; the caller treats it as best-effort.</exception>
    /// <exception cref="ObjectDisposedException">The library has already closed the session.</exception>
    internal void LogoutForDispose()
    {
        // Waits for the lock where AcquireExclusive would throw, then holds it the same way: the lease
        // takes a reference on the session handle, so a library disposed meanwhile cannot close the
        // session under the logout. A session the library has already closed throws
        // ObjectDisposedException from Hold; there is nothing left to log out of.
        Monitor.Enter(_busyLock);
        using var lease = new ExclusiveLease(_busyLock);
        if (_disposed)
            return;
        lease.Hold(_sessionHandle);

        LogoutHeld();
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    public void Logout()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "Logout");

        LogoutHeld();
    }

    // The logout itself, shared by Logout and LogoutForDispose, which differ only in how they take the
    // session lease. The caller holds it.
    private void LogoutHeld()
    {
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "CancelFunction");

        CKR rv = _pkcs11Library.C_CancelFunction(_sessionId);
        Pkcs11Exception.ThrowIfError(rv, OpCancelFunction);
    }

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
            if (disposing)
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "CreateObject");

        // Any object class may arrive here, so the refusal applies but key defaults do not.
        EnforceKeyTemplate(attributes, null);

        NativeCULong objectId = (NativeCULong)CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_CreateObject(_sessionId, template, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCreateObject);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

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

        Log.SessionTrace(_logger, (ulong)_sessionId, "CopyObject");

        // A copy can weaken the original's protection, so the same refusal applies.
        EnforceKeyTemplate(attributes, null);


        NativeCULong objectId = (NativeCULong)CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_CopyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, ref objectId);
        Pkcs11Exception.ThrowIfError(rv, OpCopyObject);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="objectHandle">Handle of object to be destroyed</param>
    public void DestroyObject(ObjectHandle objectHandle)
    {
        using var _ = AcquireExclusive();

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

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue2");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        CK_ATTRIBUTE[] template = BuildTypeOnlyTemplate(attributes);

        // The buffer handed to the module for each attribute, and its size. After every call the
        // template's pointers are reset from here and its lengths checked against it: the module fills
        // the buffers, it never chooses them.
        IntPtr[] allocatedAt = new IntPtr[template.Length];
        NativeCULong[] allocatedLen = new NativeCULong[template.Length];

        // Every block handed to the module. Ownership passes to the ObjectAttributes only at the very
        // end, so until then a failure anywhere below has to free them here or they leak — which the
        // fatal-return paths and the malformed-nested-template throw did before this.
        List<IntPtr> allocatedBlocks = [];

        // Each member of an array attribute: where it sits in its parent's block, and the buffer and
        // size given to it, so the third call is checked the same way.
        List<NestedMember> nestedMembers = [];

        // First call: determine the size of each attribute value.
        ReadAttributeValues(objectHandle, template);
        AllocateValueBuffers(template, allocatedAt, allocatedLen, allocatedBlocks);

        try
        {
            // Second call: read the values themselves.
            ReadAttributeValues(objectHandle, template);
            RestoreAndGuard(template, allocatedAt, allocatedLen);

            // Third call, needed only if some attribute is an array attribute whose children still
            // have no buffers. It rewrites the whole template, so the top level is checked again too.
            if (AllocateNestedBuffers(template, allocatedBlocks, nestedMembers))
            {
                ReadAttributeValues(objectHandle, template);
                RestoreAndGuard(template, allocatedAt, allocatedLen);
                foreach (NestedMember member in nestedMembers)
                    member.RestoreAndGuardSlot();
            }

            // Each array attribute ends up as one block its ObjectAttribute owns outright, and every
            // block not kept that way is freed (and zeroized) here rather than leaked.
            FoldAttributeArrays(template, allocatedBlocks);
        }
        catch
        {
            FreeAllocatedBlocks(allocatedBlocks);
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
    /// Builds the type-only template the first <c>C_GetAttributeValue</c> call takes: it asks the
    /// module how long each value is, so the template carries no values and needs no buffers.
    /// </summary>
    /// <remarks>
    /// Built directly rather than through <c>ObjectAttribute</c>, which is <see cref="IDisposable"/>
    /// and was being constructed here only to have its struct copied out and the wrapper dropped.
    /// Adding a <c>using</c> would have been the wrong repair: the copy in the template shares the
    /// wrapper's pointer, so disposing would leave the template pointing at freed memory the moment a
    /// type-only attribute ever allocated one. Not creating the disposable avoids the question.
    /// </remarks>
    private static CK_ATTRIBUTE[] BuildTypeOnlyTemplate(List<ulong> attributes)
    {
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

        return template;
    }

    /// <summary>
    /// Issues one <c>C_GetAttributeValue</c> call over <paramref name="template"/> and throws on a
    /// return value that is fatal to the read — all three calls of the sequence go through here, so
    /// none of them can drift from the others on what counts as fatal.
    /// </summary>
    private void ReadAttributeValues(ObjectHandle objectHandle, CK_ATTRIBUTE[] template)
    {
        CKR rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template);
        if (IsGetAttributeValueFatal(rv))
            Pkcs11Exception.ThrowIfError(rv, OpGetAttributeValue);
    }

    /// <summary>
    /// Allocates a buffer for every attribute the module reported a length for, recording both the
    /// size allocated and the block, and leaves the unreadable ones alone.
    /// </summary>
    private static void AllocateValueBuffers(CK_ATTRIBUTE[] template, IntPtr[] allocatedAt, NativeCULong[] allocatedLen, List<IntPtr> allocatedBlocks)
    {
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
            if (template[i].valueLen == NativeCULong.MaxValue)
                continue;

            allocatedLen[i] = template[i].valueLen;
            allocatedAt[i] = UnmanagedMemory.Allocate((int)(template[i].valueLen));
            template[i].value = allocatedAt[i];
            allocatedBlocks.Add(allocatedAt[i]);
        }
    }

    /// <summary>
    /// Gives every nested attribute of every array attribute a buffer, and reports whether any were
    /// found — which is exactly the question of whether a third <c>C_GetAttributeValue</c> call is
    /// needed to fill them.
    /// </summary>
    private static bool AllocateNestedBuffers(
        CK_ATTRIBUTE[] template,
        List<IntPtr> allocatedBlocks,
        List<NestedMember> nestedMembers)
    {
        bool thirdCallNeeded = false;

        for (int i = 0; i < template.Length; i++)
        {
            if (!AttributeArrayBlock.IsAttributeArray(template[i].type))
                continue;

            // PKCS#11 v2.20 page 133:
            // If the specified attribute (i.e., the attribute specified by the type field) for the object
            // cannot be revealed because the object is sensitive or unextractable, then the
            // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
            // CK_LONG, it holds -1).
            if (template[i].valueLen == NativeCULong.MaxValue)
                continue;

            thirdCallNeeded |= AllocateNestedChildBuffers(in template[i], allocatedBlocks, nestedMembers);
        }

        return thirdCallNeeded;
    }

    /// <summary>
    /// Allocates the child buffers of one array attribute, returning <see langword="false"/> when it
    /// declares no children.
    /// </summary>
    /// <exception cref="Pkcs11AttributeException">
    /// The reported length is not a whole number of <c>CK_ATTRIBUTE</c>s, so the module is not
    /// describing an attribute array at all.
    /// </exception>
    private static bool AllocateNestedChildBuffers(
        in CK_ATTRIBUTE parent,
        List<IntPtr> allocatedBlocks,
        List<NestedMember> nestedMembers)
    {
        int ckAttributeSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();

        if ((int)(parent.valueLen) % ckAttributeSize != 0)
            throw new Pkcs11AttributeException((CKA)(ulong)parent.type);

        int nestedAttrCount = (int)(parent.valueLen) / ckAttributeSize;
        if (nestedAttrCount == 0)
            return false;

        for (int j = 0; j < nestedAttrCount; j++)
        {
            IntPtr tempPointer = new(parent.value.ToInt64() + (j * ckAttributeSize));
            CK_ATTRIBUTE tempAttribute = UnmanagedMemory.Read<CK_ATTRIBUTE>(tempPointer);

            // Recorded even when unreadable (no buffer): the module must not hand one back either.
            IntPtr buffer = IntPtr.Zero;
            NativeCULong allocated = default;
            if (tempAttribute.valueLen != NativeCULong.MaxValue)
            {
                allocated = tempAttribute.valueLen;
                buffer = UnmanagedMemory.Allocate((int)allocated);
                allocatedBlocks.Add(buffer);
            }
            nestedMembers.Add(new NestedMember(tempPointer, buffer, allocated));

            tempAttribute.value = buffer;
            UnmanagedMemory.Write(tempPointer, in tempAttribute);
        }

        return true;
    }

    /// <summary>
    /// Resets every attribute's <c>pValue</c> to the buffer this session gave it, then checks the
    /// reported length against that buffer's size.
    /// </summary>
    /// <remarks>
    /// The module writes into the template (directly on Unix, through the packed copy on Windows), so
    /// it could hand back a different pointer. Restoring ours means the buffers read and freed later
    /// are always the ones this session allocated, never an address the module chose.
    /// </remarks>
    private static void RestoreAndGuard(CK_ATTRIBUTE[] template, IntPtr[] allocatedAt, NativeCULong[] allocatedLen)
    {
        for (int i = 0; i < template.Length; i++)
        {
            template[i].value = allocatedAt[i];
            GuardReportedLength(in template[i], allocatedLen[i]);
        }
    }

    /// <summary>One member of an array attribute, as this session laid it out for the third call.</summary>
    /// <param name="Slot">Where the member's <c>CK_ATTRIBUTE</c> sits in its parent's block.</param>
    /// <param name="Buffer">The buffer given to the member, or <see cref="IntPtr.Zero"/> when unreadable.</param>
    /// <param name="Allocated">The buffer's size.</param>
    private readonly record struct NestedMember(IntPtr Slot, IntPtr Buffer, NativeCULong Allocated)
    {
        /// <summary>
        /// The nested counterpart of the template-level <see cref="RestoreAndGuard"/>, applied to the
        /// member's <c>CK_ATTRIBUTE</c> at <see cref="Slot"/>.
        /// </summary>
        public void RestoreAndGuardSlot()
        {
            CK_ATTRIBUTE member = UnmanagedMemory.Read<CK_ATTRIBUTE>(Slot);
            member.value = Buffer;
            GuardReportedLength(in member, Allocated);
            UnmanagedMemory.Write(Slot, in member);
        }
    }

    /// <summary>
    /// Replaces each array attribute's parent and member buffers with one block laid out by
    /// <see cref="AttributeArrayBlock"/>, then frees every allocated block that no attribute keeps.
    /// </summary>
    /// <remarks>
    /// The members' buffers were separate allocations nobody would own once the read returned: the
    /// <see cref="ObjectAttribute"/> owns only its own value, and the views
    /// <see cref="ObjectAttribute.GetValueAsAttributeArray"/> returns own nothing. Folding them into
    /// the parent's block gives every byte one owner. On success <paramref name="allocatedBlocks"/>
    /// is emptied: what is not freed here belongs to the attributes.
    /// </remarks>
    private static void FoldAttributeArrays(CK_ATTRIBUTE[] template, List<IntPtr> allocatedBlocks)
    {
        List<IntPtr> created = [];
        try
        {
            for (int i = 0; i < template.Length; i++)
            {
                CK_ATTRIBUTE attribute = template[i];
                if (!AttributeArrayBlock.IsAttributeArray(attribute.type)
                    || attribute.value == IntPtr.Zero
                    || attribute.valueLen == NativeCULong.MaxValue
                    || (ulong)attribute.valueLen == 0)
                    continue;

                CK_ATTRIBUTE[] members = AttributeArrayBlock.ReadMembers(attribute.type, attribute.value, attribute.valueLen);
                IntPtr block = AttributeArrayBlock.Create(members, out NativeCULong arrayLength);
                created.Add(block);
                template[i].value = block;
                template[i].valueLen = arrayLength;
            }
        }
        catch
        {
            FreeAllocatedBlocks(created);
            throw;
        }

        var kept = new HashSet<IntPtr>(template.Select(a => a.value));
        Span<IntPtr> blocks = CollectionsMarshal.AsSpan(allocatedBlocks);
        for (int i = 0; i < blocks.Length; i++)
        {
            if (!kept.Contains(blocks[i]))
                UnmanagedMemory.Free(ref blocks[i]);
        }
        allocatedBlocks.Clear();
    }

    /// <summary>Releases every block allocated for a read that then failed.</summary>
    /// <remarks>
    /// Freed through a span so that <c>Free</c>'s write-back lands in the list. <c>Free</c> nulls the
    /// pointer it is given and returns early on a null one — that pair is its double-free guard, and
    /// handing it a copy of each entry threw the guard away while looking like it was using it.
    /// </remarks>
    private static void FreeAllocatedBlocks(List<IntPtr> allocatedBlocks)
    {
        Span<IntPtr> blocks = CollectionsMarshal.AsSpan(allocatedBlocks);
        for (int i = 0; i < blocks.Length; i++)
            UnmanagedMemory.Free(ref blocks[i]);
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

        throw new Pkcs11AttributeException((CKA)(ulong)attribute.type,
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetAttributeValue");


        ArgumentNullException.ThrowIfNull(attributes);

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", nameof(attributes));

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;

        CKR rv = _pkcs11Library.C_SetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template);
        Pkcs11Exception.ThrowIfError(rv, OpSetAttributeValue);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    public void FindObjectsInit(List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjectsInit");

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="objectCount">Maximum number of object handles to be returned</param>
    /// <returns>Found object handles</returns>
    public List<ObjectHandle> FindObjects(int objectCount)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindObjects");

        List<ObjectHandle> foundObjects = [];

        NativeCULong[] objects = new NativeCULong[objectCount];
        CKR rv = _pkcs11Library.C_FindObjects(_sessionId, objects, out NativeCULong foundObjectsCount);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

        int found = ReportedLength.Written(foundObjectsCount, objects.Length, OpFindObjects);
        for (int i = 0; i < found; i++)
            foundObjects.Add(new ObjectHandle((ulong)objects[i]));

        return foundObjects;
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    public void FindObjectsFinal()
    {
        using var _ = AcquireExclusive();

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

        Log.SessionTrace(_logger, (ulong)_sessionId, "FindAllObjects");

        List<ObjectHandle> foundObjects = [];

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template);
        Pkcs11Exception.ThrowIfError(rv, OpFindObjectsInit);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        try
        {
            Span<NativeCULong> objects = stackalloc NativeCULong[256];
            int found;
            do
            {
                rv = _pkcs11Library.C_FindObjects(_sessionId, objects, out NativeCULong objectCount);
                Pkcs11Exception.ThrowIfError(rv, OpFindObjects);

                found = ReportedLength.Written(objectCount, objects.Length, OpFindObjects);
                for (int i = 0; i < found; i++)
                    foundObjects.Add(new ObjectHandle((ulong)objects[i]));
            }
            while (found == objects.Length);
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
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="mechanism">Generation mechanism</param>
    /// <param name="attributes">Attributes of the new key or set of domain parameters</param>
    /// <returns>Handle of the new key or set of domain parameters</returns>
    public ObjectHandle GenerateKey(Mechanism mechanism, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.GenerateKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKey");

        // A secret key: refuse a deliberately weakened template, and supply the secure defaults when
        // the caller stated nothing — the same treatment DeriveKey and UnwrapKey already gave.
        using ReadOnlyDisposableList<ObjectAttribute> generatedDefaults = BuildSecureKeyDefaults(attributes, CKO.CKO_SECRET_KEY);
        if (generatedDefaults.Count > 0)
        {
            attributes = attributes is null ? [] : [.. attributes];
            attributes.AddRange(generatedDefaults);
        }

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        NativeCULong keyId = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKey(_sessionId, ref ckMechanism, template, ref keyId);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

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

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.GenerateKeyPair);

        if (mechanism.Type is CKM.CKM_RSA_PKCS_KEY_PAIR_GEN or CKM.CKM_RSA_X9_31_KEY_PAIR_GEN)
        {
            // Only the first CKA_MODULUS_BITS is consulted: a template carrying two is malformed, and
            // which one the token would honour is not ours to decide.
            ObjectAttribute? modulusBits =
                publicKeyAttributes.FirstOrDefault(a => a.Type == CKA.CKA_MODULUS_BITS);
            if (modulusBits is not null)
                Enforce(new RsaKeyGenerationRequest(mechanism.Type, ModulusBitsOf(modulusBits)));
        }
        else if (mechanism.Type == CKM.CKM_EC_KEY_PAIR_GEN)
        {
            // Every EC key-pair generation meets the curve allow-list here, whichever public entry point
            // it came through. As for the modulus above, only the first CKA_EC_PARAMS is consulted; with
            // none there is no curve to judge and the token rejects the incomplete template itself.
            ObjectAttribute? ecParams =
                publicKeyAttributes.FirstOrDefault(a => a.Type == CKA.CKA_EC_PARAMS);
            if (ecParams is not null)
                Enforce(new EcKeyGenerationRequest(CurveOf(ecParams)));
        }

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKeyPair");

        // The private half only. CKA_SENSITIVE / CKA_EXTRACTABLE do not belong on a public key, so
        // seeding them there would be rejected by the token; the refusal alone is enough.
        using ReadOnlyDisposableList<ObjectAttribute> privateDefaults = BuildSecureKeyDefaults(privateKeyAttributes, CKO.CKO_PRIVATE_KEY);
        if (privateDefaults.Count > 0)
        {
            privateKeyAttributes = [.. privateKeyAttributes];
            privateKeyAttributes.AddRange(privateDefaults);
        }

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CK_ATTRIBUTE[]? publicKeyTemplate = BuildTemplate(publicKeyAttributes);
        CK_ATTRIBUTE[]? privateKeyTemplate = BuildTemplate(privateKeyAttributes);

        NativeCULong publicKeyId = (NativeCULong)CK.CK_INVALID_HANDLE;
        NativeCULong privateKeyId = (NativeCULong)CK.CK_INVALID_HANDLE;

        // NSS bug 1012786: C_GenerateKeyPair (RSA in particular) can fail with CKR_FUNCTION_FAILED
        // under a transient RNG hiccup (e.g. an interrupted read()/getentropy() syscall). PKCS#11
        // v3.2 §11.1.1 explicitly distinguishes this from CKR_GENERAL_ERROR as retry-safe: "it is
        // possible that an attempt to make the exact same function call again would succeed."
        // Matches SunPKCS11's own workaround (p11_keymgmt.c, MAX_ATTEMPTS = 3) — no delay between
        // attempts, since the failure mode is a syscall interruption, not a slow-to-clear condition.
        const int maxAttempts = 3;
        CKR rv;
        int attempt = 0;
        do
        {
            rv = _pkcs11Library.C_GenerateKeyPair(_sessionId, ref ckMechanism, publicKeyTemplate, privateKeyTemplate, ref publicKeyId, ref privateKeyId);
        } while (rv == CKR.CKR_FUNCTION_FAILED && ++attempt < maxAttempts);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKeyPair);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(publicKeyAttributes);
        GC.KeepAlive(privateKeyAttributes);

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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Wrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        byte[]? wrappedKey = mechanism.Type == CKM.CKM_AES_KEY_WRAP_KWP
            ? TryWrapKeyKwp(ref ckMechanism, wrappingKeyHandle, keyHandle)
            : null;

        wrappedKey ??= CallWithLengthProbe(
            (Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), buf, lengthOnly, out len),
            OpWrapKey);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return wrappedKey;
    }

    // NSS bug: sftk_CryptInit's CKM_AES_KEY_WRAP_KWP case (softoken/pkcs11c.c) never sets
    // context->blockSize, unlike the sibling CKM_AES_KEY_WRAP/_PAD case (which sets it to 8).
    // NSC_Encrypt's NULL-probe formula (ulDataLen + 2*blockSize) therefore collapses to exactly
    // ulDataLen for KWP, silently omitting RFC 5649's ~8-byte overhead from the reported required
    // length -- and the follow-up too-small-buffer call doesn't correct it either, since NSS only
    // updates the output length parameter when the call succeeds. RFC 5649's wrapped length is
    // fully determined by the input length alone, so this mechanism skips the token's (for this
    // one case, untrustworthy) length probe entirely and computes the buffer size directly --
    // the same reasoning as MLKemPkcs11.EncapsulateCore handing ML-KEM a pre-sized buffer instead
    // of a NULL-buffer probe SoftHSM doesn't honour. Safe to remove once a fixed NSS is vendored.
    //
    // Only secret keys carry CKA_VALUE_LEN. A CKO_PRIVATE_KEY wraps as a PKCS#8-packaged byte
    // string whose length isn't derivable from any client-visible attribute, so this workaround
    // cannot apply there -- returns null ("not applicable") and WrapKey falls back to the normal
    // probing path. That path still hits the underlying NSS bug for a private key wrapped via
    // KWP, same as before this workaround existed, but at least fails with the token's own
    // CKR_BUFFER_TOO_SMALL rather than an unrelated "CKA_VALUE_LEN could not be read" from here.
    private byte[]? TryWrapKeyKwp(ref CK_MECHANISM ckMechanism, ObjectHandle wrappingKeyHandle, ObjectHandle keyHandle)
    {
        using ReadOnlyDisposableList<ObjectAttribute> classAttrs = GetAttributeValue(keyHandle, [CKA.CKA_CLASS]);
        if (classAttrs[0].GetValueAsUlong() != (ulong)CKO.CKO_SECRET_KEY)
            return null;

        using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(keyHandle, [CKA.CKA_VALUE_LEN]);
        ulong valueLen = attrs[0].GetValueAsUlong();
        ulong wrappedLen = 8 + ((valueLen + 7) / 8 * 8);

        byte[] buffer = new byte[wrappedLen];
        CKR rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), buffer, lengthOnly: false, out NativeCULong len);
        Pkcs11Exception.ThrowIfError(rv, OpWrapKey);

        return ReportedLength.Trim(buffer, len, OpWrapKey);
    }

    /// <summary>
    /// Unwraps a wrapped key using the given unwrapping key and mechanism. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">Key-unwrap mechanism.</param>
    /// <param name="unwrappingKeyHandle">Handle of the unwrapping key (private RSA, AES-WRAP key, etc.).</param>
    /// <param name="wrappedKey">Wrapped key bytes to unwrap.</param>
    /// <param name="attributes">Template for the resulting unwrapped key.</param>
    /// <returns>Handle of the newly unwrapped key.</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, ReadOnlySpan<byte> wrappedKey, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Unwrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Unwrapping decrypts a key blob into a new token object. Without secure defaults a caller
        // could land an extractable, non-sensitive key — silently downgrading the posture the key
        // template builders establish. Append CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the
        // caller omitted them; an explicit insecure value requires a policy that permits it (throws otherwise).
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes, null);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults);

        NativeCULong unwrappedKey = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, ref ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, template, ref unwrappedKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
        GC.KeepAlive(secureDefaults);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)unwrappedKey);
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
        ArgumentNullException.ThrowIfNull(wrappedKey);
        return UnwrapKey(mechanism, unwrappingKeyHandle, wrappedKey.AsSpan(), attributes);
    }

    /// <summary>
    /// The named curve a <c>CKA_EC_PARAMS</c> value selects, or the default (no-OID) curve when it names
    /// none — explicit curve parameters, a printable curve name, or an unreadable value. The default
    /// curve is on no allow-list, so a restrictive policy refuses it while AllowInsecure still permits it.
    /// </summary>
    /// <summary>
    /// Submits the type of the key an ECDH derivation or KEM will use, so a policy can refuse key
    /// agreement with a key it would never have let the caller generate (FipsOnly: X25519/X448). The
    /// mechanism alone cannot tell: <c>CKM_ECDH1_DERIVE</c> serves both Weierstrass and Montgomery keys.
    /// </summary>
    /// <remarks>
    /// A key whose <c>CKA_KEY_TYPE</c> cannot be read is left to the token. That attribute is never
    /// sensitive, so failing to read it means the handle itself is unusable and the native call that
    /// follows fails the same way.
    /// </remarks>
    private void EnforceKeyAgreementKey(Mechanism mechanism, ObjectHandle key)
    {
        if (mechanism.Type is not (CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE))
            return;

        CKK keyType;
        try
        {
            using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(key, [CKA.CKA_KEY_TYPE]);
            if (attrs[0].CannotBeRead)
                return;
            keyType = (CKK)attrs[0].GetValueAsUlong();
        }
        catch (Exception ex) when (ex is Pkcs11Exception or Pkcs11AttributeException)
        {
            return;
        }

        Enforce(new KeyAgreementKeyRequest(mechanism.Type, keyType));
    }

    // A modulus length is judged as an int. One beyond int.MaxValue is not a key any token can make; it
    // is reported as int.MaxValue, which every policy's minimum allows, so the token refuses it itself.
    private static int ModulusBitsOf(ObjectAttribute modulusBits)
    {
        ulong bits = modulusBits.GetValueAsUlong();
        return bits > int.MaxValue ? int.MaxValue : (int)bits;
    }

    private static Pkcs11ECCurve CurveOf(ObjectAttribute ecParams)
    {
        try
        {
            return Pkcs11ECCurve.FromEcParams(ecParams.GetValueAsByteArray());
        }
        catch (Exception ex) when (ex is ArgumentException or Pkcs11AttributeException)
        {
            return default;
        }
    }

    /// <summary>
    /// Submits a creation template to the policy. <paramref name="objectClass"/> is the class the
    /// creating path knows for certain; paths that take an arbitrary template pass null rather than
    /// parse the caller's CKA_CLASS.
    /// </summary>
    private void EnforceKeyTemplate(List<ObjectAttribute>? attributes, CKO? objectClass)
    {
        if (attributes is null) return;
        Enforce(new KeyTemplateRequest(objectClass, attributes));
    }

    /// <summary>
    /// Runs <see cref="EnforceKeyTemplate"/>, then returns the secure-default attributes to
    /// append for any the caller omitted — <c>CKA_SENSITIVE=true</c> and <c>CKA_EXTRACTABLE=false</c>.
    /// </summary>
    /// <remarks>
    /// Used by the paths that create a secret or private key from a template, so they all start from
    /// the same posture. The returned attributes own unmanaged buffers and must be disposed by the
    /// caller. Note the asymmetry with the refusal: <c>CKA_EXTRACTABLE=false</c> is supplied as a
    /// default here, but an explicit <c>CKA_EXTRACTABLE=true</c> is not refused — only
    /// <c>CKA_SENSITIVE=false</c> is.
    /// </remarks>
    private ReadOnlyDisposableList<ObjectAttribute> BuildSecureKeyDefaults(List<ObjectAttribute>? attributes, CKO? objectClass)
    {
        EnforceKeyTemplate(attributes, objectClass);

        bool hasSensitive = attributes?.Any(a => a.Type == CKA.CKA_SENSITIVE) ?? false;
        bool hasExtractable = attributes?.Any(a => a.Type == CKA.CKA_EXTRACTABLE) ?? false;

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
    /// <remarks>
    /// <b>Callers must <c>GC.KeepAlive</c> the source collection until after the native call.</b> The
    /// returned array holds raw copies of each attribute's <c>pValue</c> pointer and no reference to
    /// the <see cref="ObjectAttribute"/> that owns the buffer, so once this returns, nothing else
    /// keeps those attributes reachable — and <see cref="ObjectAttribute"/> has a finalizer that
    /// zeroizes and frees. Left unrooted, a caller passing a temporary template can have its buffers
    /// wiped mid-call.
    /// </remarks>
    private static CK_ATTRIBUTE[]? BuildTemplate(List<ObjectAttribute>? attributes)
    {
        if (attributes is null)
            return null;

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
    private static CK_ATTRIBUTE[]? BuildTemplateWithDefaults(List<ObjectAttribute>? attributes, ReadOnlyDisposableList<ObjectAttribute> secureDefaults)
    {
        int attrCount = attributes?.Count ?? 0;
        int total = attrCount + secureDefaults.Count;
        if (total == 0)
            return null;

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[total];
        int idx = 0;
        for (int i = 0; i < attrCount; i++)
            template[idx++] = attributes![i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;
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

    /// <summary>One step of a Cryptoki two-call length probe: invoke with <paramref name="lengthOnly"/> to
    /// learn the size, then again with the allocated buffer. Capacity comes from the buffer itself, so
    /// the two can never disagree.</summary>
    private delegate CKR LengthProbedCall(Span<byte> buffer, bool lengthOnly, out NativeCULong length);

    /// <summary>
    /// A <see cref="LengthProbedCall"/> that also takes the operation's input. The input is passed in
    /// rather than captured, because a lambda cannot capture a span, and copying it into an array to
    /// capture would leave a plaintext copy on the heap.
    /// </summary>
    private delegate CKR InputLengthProbedCall(ReadOnlySpan<byte> input, Span<byte> buffer, bool lengthOnly, out NativeCULong length);

    /// <inheritdoc cref="CallWithLengthProbe(ReadOnlySpan{byte}, InputLengthProbedCall, string)"/>
    private static byte[] CallWithLengthProbe(LengthProbedCall call, string operation)
        => CallWithLengthProbe([], (ReadOnlySpan<byte> _, Span<byte> buffer, bool lengthOnly, out NativeCULong length) => call(buffer, lengthOnly, out length), operation);

    /// <summary>
    /// Runs the PKCS#11 two-call pattern: query the output length, allocate, fill,
    /// and return exactly what the module reports writing.
    /// </summary>
    /// <remarks>
    /// Every length the module reports is checked through <see cref="ReportedLength"/>: one it cannot
    /// have written (larger than the buffer) or cannot mean (<c>CK_UNAVAILABLE_INFORMATION</c>) is
    /// refused, never padded or truncated. A <c>CKR_BUFFER_TOO_SMALL</c> on the fill call leaves the
    /// operation active (PKCS#11 v3.2 §5.2), so it is retried once with the size the module then asks
    /// for. A trimmed buffer is zeroized, since for a decryption it holds plaintext.
    /// </remarks>
    private static byte[] CallWithLengthProbe(ReadOnlySpan<byte> input, InputLengthProbedCall call, string operation)
    {
        CKR rv = call(input, default, lengthOnly: true, out NativeCULong reported);
        Pkcs11Exception.ThrowIfError(rv, operation);

        byte[] buffer = new byte[ReportedLength.ForAllocation(reported, operation)];
        rv = call(input, buffer, lengthOnly: false, out reported);
        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            buffer = new byte[ReportedLength.ForAllocation(reported, operation)];
            rv = call(input, buffer, lengthOnly: false, out reported);
        }
        Pkcs11Exception.ThrowIfError(rv, operation);

        return ReportedLength.Trim(buffer, reported, operation);
    }

    /// <summary>
    /// One <c>C_*Update</c> call of a multi-part transform. Every such entry point in Cryptoki has
    /// this shape — input, output, bytes written — which is what lets the five streaming loops share
    /// <see cref="PumpStreamThrough"/>.
    /// </summary>
    private delegate CKR StreamingUpdate(ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen);

    /// <summary>
    /// Drives a multi-part transform over a stream: read a block, transform it, write the result,
    /// until the input is exhausted.
    /// </summary>
    /// <remarks>
    /// The output buffer is sized speculatively from <paramref name="bufferLength"/> and grown on
    /// demand, because a mechanism can expand its input (block padding, or an AEAD emitting a tag)
    /// and a token may report the true size only once it has seen the block. <c>CKR_BUFFER_TOO_SMALL</c>
    /// is a length report rather than a failure here: PKCS#11 v3.2 §5.2 requires the operation to stay
    /// active so the same block can be resubmitted, which is why the retry passes the same input
    /// again. A grown buffer is kept for the following blocks rather than re-grown each time.
    /// </remarks>
    private static void PumpStreamThrough(
        Stream inputStream,
        Stream outputStream,
        int bufferLength,
        StreamingUpdate update,
        string operation)
    {
        byte[] input = new byte[bufferLength];
        byte[] output = new byte[bufferLength];
        try
        {
            int bytesRead;
            while ((bytesRead = inputStream.Read(input, 0, input.Length)) > 0)
            {
                CKR rv = update(input.AsSpan(0, bytesRead), output, out NativeCULong outputLen);
                if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, operation);

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    CryptographicOperations.ZeroMemory(output);
                    output = new byte[ReportedLength.ForAllocation(outputLen, operation)];

                    rv = update(input.AsSpan(0, bytesRead), output, out outputLen);
                    Pkcs11Exception.ThrowIfError(rv, operation);
                }

                outputStream.Write(output, 0, ReportedLength.Written(outputLen, output.Length, operation));
            }
        }
        finally
        {
            // One side of the transform is plaintext; neither buffer outlives the call with it.
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    /// <summary>Initializes the non-digest half of a combined operation (<c>C_EncryptInit</c> / <c>C_DecryptInit</c>).</summary>
    private delegate CKR TransformInit(ref CK_MECHANISM mechanism, NativeCULong keyHandle);

    /// <summary>
    /// The non-digest half of a combined digest-and-transform operation: the three native calls that
    /// differ between <see cref="DigestEncrypt(Mechanism, Mechanism, ObjectHandle, Stream, Stream, int)"/>
    /// and <see cref="DecryptDigest(Mechanism, Mechanism, ObjectHandle, Stream, Stream, int)"/>, plus
    /// the <c>CKF_*</c> bit naming that half when an unwind has to cancel it.
    /// </summary>
    private sealed record CombinedTransform(
        TransformInit Init, string InitOperation,
        StreamingUpdate Update, string UpdateOperation,
        LengthProbedCall Final, string FinalOperation,
        ulong CancelFlag);

    /// <summary>
    /// Runs a digest interleaved with a transform over a stream — <c>C_DigestEncryptUpdate</c> and
    /// <c>C_DecryptDigestUpdate</c> are the same algorithm with the roles of the two buffers swapped,
    /// so both directions are driven from here rather than written twice.
    /// </summary>
    /// <remarks>
    /// The digest and the transform are two independent active operations on the session, not one, so
    /// each is finalized separately and the unwind cancels whichever is still live. The transform's
    /// init can fail after the digest's succeeded, which is why the cancel is computed from what
    /// actually completed rather than from where the exception came from.
    /// </remarks>
    /// <returns>The digest over the input, as read by <c>C_DigestFinal</c>.</returns>
    private byte[] DigestAndTransformStream(
        Mechanism digestingMechanism,
        Mechanism transformMechanism,
        ObjectHandle keyHandle,
        Stream inputStream,
        Stream outputStream,
        int bufferLength,
        CombinedTransform transform,
        string operationName)
    {
        // Both mechanisms marshal into the same scope: the two operations run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckDigestingMechanism = digestingMechanism.Marshal(scope, out Pkcs11ParameterBlock? digestParams);

        using var operation = BeginOperation(operationName);
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        CK_MECHANISM ckTransformMechanism = transformMechanism.Marshal(scope, out Pkcs11ParameterBlock? transformParams);

        rv = transform.Init(ref ckTransformMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(transform.CancelFlag, rv, transform.InitOperation);

        PumpStreamThrough(inputStream, outputStream, bufferLength, transform.Update, transform.UpdateOperation);

        // Whatever the transform held back — a partial block, or an AEAD tag.
        byte[] lastPart = CallWithLengthProbe(transform.Final, transform.FinalOperation);
        operation.End(transform.CancelFlag);

        if (lastPart.Length > 0)
            outputStream.Write(lastPart, 0, lastPart.Length);

        byte[] digest = CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong length) => _pkcs11Library.C_DigestFinal(_sessionId, buffer, lengthOnly, out length),
            OpDigestFinal);
        operation.Completed();

        digestingMechanism.AbsorbOutput(digestParams);
        transformMechanism.AbsorbOutput(transformParams);

        return digest;
    }

    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Encrypt");
        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_ENCRYPT, rv, OpEncryptInit);

        // Size the output for the largest single-block expansion a symmetric mechanism adds — a full
        // block of PKCS padding (AES block = 16) or a 16-byte AEAD tag — so block and AEAD ciphers
        // finish in one C_Encrypt without a null-length probe (which makes some AEAD tokens run the
        // whole operation on the probe). This also sidesteps NSS softoken's broken single-part CBC-PAD
        // path, whose short-buffer C_Encrypt feeds the input through EncryptUpdate/Final and does not
        // report the required length. RSA and other output-larger-than-input mechanisms still grow via
        // the CKR_BUFFER_TOO_SMALL retry below.
        byte[] encryptedData = new byte[data.Length + 16];
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, encryptedData, lengthOnly: false, out NativeCULong encryptedDataLen);

        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            encryptedData = new byte[ReportedLength.ForAllocation(encryptedDataLen, OpEncrypt)];
            rv = _pkcs11Library.C_Encrypt(_sessionId, data, encryptedData, lengthOnly: false, out encryptedDataLen);

            // PKCS#11 v3.2 §5.2 requires CKR_BUFFER_TOO_SMALL to leave the operation active for a retry.
            // NSS softoken's classic C_Encrypt violates this — it terminates the operation, so the retry
            // above returns CKR_OPERATION_NOT_INITIALIZED. Recover by re-initializing, querying the length,
            // then encrypting once. Reachable only for output-larger-than-input
            // mechanisms (e.g. RSA) that exceed the padded buffer above; unreachable on spec-compliant
            // tokens, whose retry already returned CKR_OK.
            if (rv == CKR.CKR_OPERATION_NOT_INITIALIZED)
            {
                rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
                Pkcs11Exception.ThrowIfError(rv, OpEncryptInit);

                rv = _pkcs11Library.C_Encrypt(_sessionId, data, default, lengthOnly: true, out NativeCULong probeLen);
                Pkcs11Exception.ThrowIfError(rv, OpEncrypt);

                encryptedData = new byte[ReportedLength.ForAllocation(probeLen, OpEncrypt)];
                rv = _pkcs11Library.C_Encrypt(_sessionId, data, encryptedData, lengthOnly: false, out encryptedDataLen);
            }
        }

        Pkcs11Exception.ThrowIfError(rv, OpEncrypt);
        operation.Completed();

        // Inside the scope's lifetime: the parameter block the token may have written into (an AEAD
        // IV, say) is still allocated. After `scope` is disposed the bytes are zeroized and freed.
        mechanism.AbsorbOutput(mechParams);

        encryptedData = ReportedLength.Trim(encryptedData, encryptedDataLen, OpEncrypt);

        return encryptedData;
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
        ArgumentNullException.ThrowIfNull(data);
        return Encrypt(mechanism, keyHandle, data.AsSpan());
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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Encrypt);

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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Encrypt");
        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_ENCRYPT, rv, OpEncryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_EncryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpEncryptUpdate);

        byte[]? lastEncryptedPart = null;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);

        lastEncryptedPart = new byte[ReportedLength.ForAllocation(lastEncryptedPartLen, OpEncryptFinal)];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, lengthOnly: false, out lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        outputStream.Write(lastEncryptedPart, 0, ReportedLength.Written(lastEncryptedPartLen, lastEncryptedPart.Length, OpEncryptFinal));
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        EnforceMessage(mechanism, messageParams, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageEncrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);
        CKR rv = _pkcs11Library.C_MessageEncryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageEncryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            Pkcs11ParameterBlock messageBlock = messageParams.BuildMarshalable(scope);

            rv = _pkcs11Library.C_EncryptMessage(
                _sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length,
                associatedData,
                plaintext,
                null, out NativeCULong ctLen);
            Pkcs11Exception.ThrowIfError(rv, "C_EncryptMessage (length probe)");

            byte[] ct = new byte[ReportedLength.ForAllocation(ctLen, OpEncryptMessage)];
            rv = _pkcs11Library.C_EncryptMessage(
                _sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length,
                associatedData,
                plaintext,
                ct, out ctLen);
            Pkcs11Exception.ThrowIfError(rv, OpEncryptMessage);

            // The token wrote the authentication tag into the scope-owned block; copy it back into
            // the wrapper before `scope` is disposed and the bytes are zeroized.
            messageParams.AbsorbOutput(messageBlock);

            return ReportedLength.Trim(ct, ctLen, OpEncryptMessage);
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
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The decryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to decrypt with.</param>
    /// <param name="encryptedData">Ciphertext to decrypt.</param>
    /// <returns>A freshly-allocated byte array containing the plaintext.</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Decrypt");
        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_DECRYPT, rv, OpDecryptInit);

        // Use input length as the initial output buffer size — avoids a null-probe call
        // that causes AEAD tokens (e.g. SoftHSM2) to run full tag verification and return
        // an opaque error instead of the plaintext length. Resize via CKR_BUFFER_TOO_SMALL
        // if the token needs more space (e.g. padding expansion on some mechanisms).
        byte[] decryptedData = new byte[encryptedData.Length];
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, decryptedData, lengthOnly: false, out NativeCULong decryptedDataLen);

        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            CryptographicOperations.ZeroMemory(decryptedData);
            decryptedData = new byte[ReportedLength.ForAllocation(decryptedDataLen, OpDecrypt)];
            rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, decryptedData, lengthOnly: false, out decryptedDataLen);
        }

        Pkcs11Exception.ThrowIfError(rv, OpDecrypt);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        return ReportedLength.Trim(decryptedData, decryptedDataLen, OpDecrypt);
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
        ArgumentNullException.ThrowIfNull(encryptedData);
        return Decrypt(mechanism, keyHandle, encryptedData.AsSpan());
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

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Decrypt);

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

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Decrypt");
        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_DECRYPT, rv, OpDecryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_DecryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpDecryptUpdate);

        byte[]? lastPart = null;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        lastPart = new byte[ReportedLength.ForAllocation(lastPartLen, OpDecryptFinal)];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, lengthOnly: false, out lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        outputStream.Write(lastPart, 0, ReportedLength.Written(lastPartLen, lastPart.Length, OpDecryptFinal));
        CryptographicOperations.ZeroMemory(lastPart);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        EnforceMessage(mechanism, messageParams, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageDecrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);
        CKR rv = _pkcs11Library.C_MessageDecryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageDecryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            Pkcs11ParameterBlock messageBlock = messageParams.BuildMarshalable(scope);

            rv = _pkcs11Library.C_DecryptMessage(
                _sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length,
                associatedData,
                ciphertext,
                null, out NativeCULong ptLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DecryptMessage (length probe)");

            byte[] pt = new byte[ReportedLength.ForAllocation(ptLen, OpDecryptMessage)];
            rv = _pkcs11Library.C_DecryptMessage(
                _sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length,
                associatedData,
                ciphertext,
                pt, out ptLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptMessage);

            messageParams.AbsorbOutput(messageBlock);

            return ReportedLength.Trim(pt, ptLen, OpDecryptMessage);
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
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Sign);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Sign");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Sign");
        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        operation.Begin(CKF.CKF_SIGN, rv, OpSignInit);

        byte[] signature = CallWithLengthProbe(data,
            (ReadOnlySpan<byte> input, Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_Sign(_sessionId, input, buf, lengthOnly, out len),
            OpSign);
        operation.Completed();

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return signature;
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the given
    /// mechanism and key. Throws <see cref="CryptoPolicyViolationException"/> if
    /// <paramref name="mechanism"/> is insecure-by-default and the session's policy refuses the mechanism.
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


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Verify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        rv = _pkcs11Library.C_Verify(_sessionId, data, signature);
        operation.Completed(); // C_Verify ends the operation whatever it returns
        isValid = IsVerified(rv, OpVerify);

        mechanism.AbsorbOutput(mechParams);
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
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        Verify(mechanism, keyHandle, data.AsSpan(), signature.AsSpan(), out isValid);
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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Verify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part.AsSpan(0, bytesRead));
            Pkcs11Exception.ThrowIfError(rv, OpVerifyUpdate);
        }

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature);
        // C_VerifyFinal always finalizes — whether the signature was valid, invalid, or
        // the call failed with any other CKR — the verify operation is consumed.
        operation.Completed();
        isValid = IsVerified(rv, OpVerifyFinal);

        mechanism.AbsorbOutput(mechParams);
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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifyRecover");

        ArgumentNullException.ThrowIfNull(signature);

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifyRecover");
        CKR rv = _pkcs11Library.C_VerifyRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY_RECOVER, rv, OpVerifyRecoverInit);

        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, default, lengthOnly: true, out NativeCULong dataLen);
        Pkcs11Exception.ThrowIfError(rv, OpVerifyRecover);

        byte[] data = new byte[ReportedLength.ForAllocation(dataLen, OpVerifyRecover)];
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, data, lengthOnly: false, out dataLen);
        operation.Completed(); // the call with a buffer ends the operation whatever it returns
        isValid = IsVerified(rv, OpVerifyRecover);

        mechanism.AbsorbOutput(mechParams);

        if (!isValid)
        {
            // Nothing was recovered, and the reported length is not one to trust.
            CryptographicOperations.ZeroMemory(data);
            return [];
        }
        return ReportedLength.Trim(data, dataLen, OpVerifyRecover);
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

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

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

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

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

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        // Both mechanisms marshal into the same scope: the two operations run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckVerificationMechanism = verificationMechanism.Marshal(scope, out Pkcs11ParameterBlock? verifyParams);

        using var operation = BeginOperation("DecryptVerify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckVerificationMechanism, (NativeCULong)(verificationKeyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        CK_MECHANISM ckDecryptionMechanism = decryptionMechanism.Marshal(scope, out Pkcs11ParameterBlock? decryptParams);

        rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(decryptionKeyHandle.ObjectId));
        operation.Begin(CKF.CKF_DECRYPT, rv, OpDecryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpDecryptVerifyUpdate);

        byte[]? lastPart = null;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        lastPart = new byte[ReportedLength.ForAllocation(lastPartLen, OpDecryptFinal)];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, lengthOnly: false, out lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
        operation.End(CKF.CKF_DECRYPT);

        outputStream.Write(lastPart, 0, ReportedLength.Written(lastPartLen, lastPart.Length, OpDecryptFinal));
        CryptographicOperations.ZeroMemory(lastPart);

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature);
        operation.Completed(); // C_VerifyFinal ends the operation whatever it returns
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

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("DigestKey");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        rv = _pkcs11Library.C_DigestKey(_sessionId, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDigestKey);

        rv = _pkcs11Library.C_DigestFinal(_sessionId, default, lengthOnly: true, out NativeCULong digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

        byte[] digest = new byte[ReportedLength.ForAllocation(digestLen, OpDigestFinal)];
        rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, lengthOnly: false, out digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        return ReportedLength.Trim(digest, digestLen, OpDigestFinal);
    }

    /// <summary>
    /// Computes a digest over <paramref name="data"/> using the given mechanism. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list (raw MD5 / SHA-1) and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The digest mechanism (typically <see cref="CKM.CKM_SHA256"/> or stronger).</param>
    /// <param name="data">Data to digest.</param>
    /// <returns>Digest bytes (length depends on the mechanism — 32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Digest");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        byte[] digest = CallWithLengthProbe(data,
            (ReadOnlySpan<byte> input, Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_Digest(_sessionId, input, buf, lengthOnly, out len),
            OpDigest);
        operation.Completed();

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return digest;
    }

    /// <summary>
    /// Digests single-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="data">Data to be digested</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return Digest(mechanism, data.AsSpan());
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

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

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

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Digest");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_DigestUpdate(_sessionId, part.AsSpan(0, bytesRead));
            Pkcs11Exception.ThrowIfError(rv, OpDigestUpdate);
        }

        rv = _pkcs11Library.C_DigestFinal(_sessionId, default, lengthOnly: true, out NativeCULong digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);

        byte[] digest = new byte[ReportedLength.ForAllocation(digestLen, OpDigestFinal)];
        rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, lengthOnly: false, out digestLen);
        Pkcs11Exception.ThrowIfError(rv, OpDigestFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        return ReportedLength.Trim(digest, digestLen, OpDigestFinal);
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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, encryptionMechanism, nameof(encryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        return DigestAndTransformStream(
            digestingMechanism, encryptionMechanism, keyHandle, inputStream, outputStream, bufferLength,
            new CombinedTransform(
                Init: (ref CK_MECHANISM mechanism, NativeCULong key)
                    => _pkcs11Library.C_EncryptInit(_sessionId, ref mechanism, key),
                InitOperation: OpEncryptInit,
                Update: (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                    => _pkcs11Library.C_DigestEncryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
                UpdateOperation: OpDigestEncryptUpdate,
                Final: (Span<byte> buffer, bool lengthOnly, out NativeCULong length)
                    => _pkcs11Library.C_EncryptFinal(_sessionId, buffer, lengthOnly, out length),
                FinalOperation: OpEncryptFinal,
                CancelFlag: CKF.CKF_ENCRYPT),
            "DigestEncrypt");
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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

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

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, decryptionMechanism, nameof(decryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        return DigestAndTransformStream(
            digestingMechanism, decryptionMechanism, keyHandle, inputStream, outputStream, bufferLength,
            new CombinedTransform(
                Init: (ref CK_MECHANISM mechanism, NativeCULong key)
                    => _pkcs11Library.C_DecryptInit(_sessionId, ref mechanism, key),
                InitOperation: OpDecryptInit,
                Update: (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                    => _pkcs11Library.C_DecryptDigestUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
                UpdateOperation: OpDecryptDigestUpdate,
                Final: (Span<byte> buffer, bool lengthOnly, out NativeCULong length)
                    => _pkcs11Library.C_DecryptFinal(_sessionId, buffer, lengthOnly, out length),
                FinalOperation: OpDecryptFinal,
                CancelFlag: CKF.CKF_DECRYPT),
            "DecryptDigest");
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object. Secure defaults
    /// (<c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c>) are applied to the result template;
    /// an explicit insecure value requires a policy that permits it (see <see cref="ICryptoPolicy"/>).
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Derive);
        EnforceKeyAgreementKey(mechanism, baseKeyHandle);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DeriveKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Deriving produces a new key object on the token. Apply the same secure defaults as UnwrapKey
        // (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the caller omitted them); an explicit insecure
        // value requires a policy that permits it (throws otherwise). See BuildSecureKeyDefaults. Trusted internal
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes, null);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults);

        NativeCULong derivedKey = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, ref ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, ref derivedKey);
        Pkcs11Exception.ThrowIfError(rv, OpDeriveKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
        GC.KeepAlive(secureDefaults);

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

        Log.SessionTrace(_logger, (ulong)_sessionId, "SeedRandom");

        // The caller's entropy goes straight to the token: no copy to zero on the way out.
        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed);
        Pkcs11Exception.ThrowIfError(rv, OpSeedRandom);
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SeedRandom");

        ArgumentNullException.ThrowIfNull(seed);

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed);
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateRandom");

        // The token fills the caller's span directly. There is no transient array holding a second
        // copy of freshly generated key material, which is the point of passing a span you control.
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, destination);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateRandom);
        return destination.Length;
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="length">Length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>Generated random or pseudo-random data</returns>
    public byte[] GenerateRandom(int length)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateRandom");

        if (length < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(length));

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        Enforce(mechanism, CryptoOperation.Encapsulate);
        EnforceKeyAgreementKey(mechanism, encapsulatingPublicKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "EncapsulateKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // The encapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong ctLen;
        NativeCULong sharedHandle = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv;
        byte[] ct;

        if (expectedCiphertextLen > 0)
        {
            // Single-call: the exact ciphertext size is known, so hand the token a correctly-sized
            // buffer and let it fill it in one shot. This is the spec-correct path on every token
            // and the only correct path on SoftHSM, whose C_EncapsulateKey ignores a NULL buffer
            // (no length probe) and performs a side-effectful encapsulation on each call.
            ct = new byte[expectedCiphertextLen];
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                ct, lengthOnly: false, out ctLen, ref sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }
        else
        {
            // Two-call: query size first, then real encaps (size unknown to the caller).
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                default, lengthOnly: true, out ctLen, ref sharedHandle);
            // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome: the token populated
            // ctLen even though the (null) output buffer was inadequate (PKCS#11 v3.2 §5.2).
            // Only a genuine error aborts the probe.
            if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_EncapsulateKey (length probe)");

            // A token that ignores the probe (SoftHSM does) reports no size at all. Continuing would
            // allocate an empty buffer and hand the caller an empty ciphertext for an encapsulation
            // the token really performed, side effects and all — so fail here instead. The CKR is
            // synthesized: no native call failed, but the caller is who must act, and
            // CKR_BUFFER_TOO_SMALL maps to Pkcs11ArgumentException, which says so. Callers that know
            // the size pass expectedCiphertextLen and never reach this path.
            if (ctLen == (NativeCULong)0)
                throw Pkcs11Exception.Create(CKR.CKR_BUFFER_TOO_SMALL,
                    "C_EncapsulateKey (length probe reported no size — pass expectedCiphertextLen)");

            ct = new byte[ReportedLength.ForAllocation(ctLen, OpEncapsulateKey)];
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                ct, lengthOnly: false, out ctLen, ref sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }

        mechanism.AbsorbOutput(mechParams);

        ct = ReportedLength.Trim(ct, ctLen, OpEncapsulateKey);

        // Root the managed attributes past every C_EncapsulateKey call above (probe and real):
        // the template holds raw copies of their pValue pointers.
        GC.KeepAlive(sharedKeyTemplate);
        GC.KeepAlive(secureDefaults);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        Enforce(mechanism, CryptoOperation.Decapsulate);
        EnforceKeyAgreementKey(mechanism, decapsulatingPrivateKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecapsulateKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // The decapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong sharedHandle = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DecapsulateKey(
            _sessionId, ref ckMechanism, (NativeCULong)decapsulatingPrivateKey.ObjectId,
            template,
            ciphertext, ref sharedHandle);
        Pkcs11Exception.ThrowIfError(rv, OpDecapsulateKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once the loop above returns.
        GC.KeepAlive(sharedKeyTemplate);
        GC.KeepAlive(secureDefaults);

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

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Wrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKeyAuthenticated");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CKR rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            associatedData, default, lengthOnly: true, out NativeCULong wrappedLen);
        // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome (PKCS#11 v3.2 §5.2):
        // the token populated wrappedLen despite the (null) output buffer. Only a genuine
        // error aborts the probe.
        if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
            Pkcs11Exception.ThrowIfError(rv, "C_WrapKeyAuthenticated (length probe)");

        byte[] wrapped = new byte[ReportedLength.ForAllocation(wrappedLen, OpWrapKeyAuthenticated)];
        rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            associatedData, wrapped, lengthOnly: false, out wrappedLen);
        Pkcs11Exception.ThrowIfError(rv, OpWrapKeyAuthenticated);

        mechanism.AbsorbOutput(mechParams);

        return ReportedLength.Trim(wrapped, wrappedLen, OpWrapKeyAuthenticated);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappedKeyTemplate);
        Enforce(mechanism, CryptoOperation.Unwrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKeyAuthenticated");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Authenticated unwrap lands a new key object on the token, exactly as UnwrapKey does. Apply the
        // same secure defaults (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(unwrappedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[unwrappedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < unwrappedKeyTemplate.Count; i++)
            template[idx++] = unwrappedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong newKey = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)unwrappingKey.ObjectId,
            wrappedKey,
            template,
            associatedData, ref newKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKeyAuthenticated);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once the loop above returns.
        GC.KeepAlive(unwrappedKeyTemplate);
        GC.KeepAlive(secureDefaults);

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

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifySignature");
        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            signature);
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifySignatureInit);

        rv = _pkcs11Library.C_VerifySignature(_sessionId, data);
        operation.Completed(); // C_VerifySignature ends the operation whatever it returns
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(inputStream);
        if (bufferLength < 1)
            throw new ArgumentException("Value has to be a positive number.", nameof(bufferLength));
        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature(stream)");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifySignature");
        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            signature);
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifySignatureInit);

        byte[] buffer = new byte[bufferLength];
        int read;
        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifySignatureUpdate(_sessionId, buffer.AsSpan(0, read));
            Pkcs11Exception.ThrowIfError(rv, OpVerifySignatureUpdate);
        }

        rv = _pkcs11Library.C_VerifySignatureFinal(_sessionId);
        // C_VerifySignatureFinal always finalizes — whether the signature was valid, invalid, or
        // the call failed with any other CKR — the verify operation is consumed.
        operation.Completed();
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

        Log.SessionGetValidationFlags(_logger, (ulong)_sessionId, (ulong)validationType);

        NativeCULong flags = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetSessionValidationFlags(_sessionId, (NativeCULong)(ulong)validationType, ref flags);
        Pkcs11Exception.ThrowIfError(rv, OpGetSessionValidationFlags);

        return (ulong)flags;
    }
}
