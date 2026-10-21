using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The native side of a <see cref="Pkcs11Session"/>: the logical connection between an application
/// and a token, its spec-level calls, and the policy enforced on them.
/// </summary>
internal sealed partial class Pkcs11SessionCore : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed. Written under <see cref="_busyLock"/>,
    /// but read outside it by the property guards, so it is <see langword="volatile"/>: a disposal on one
    /// thread has to be visible to the next caller on another without the reader taking the lock.
    /// </summary>
    private volatile bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private readonly ILogger _logger;

    // The slot this session was opened on: what CKM_PKCS5_PBKD2 asks about to pick its parameter layout.
    private readonly NativeCULong _slotId;

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private readonly LowLevelPkcs11Library _pkcs11Library;

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
    /// Lock object guarding concurrent native-call access to this <see cref="Pkcs11SessionCore"/>.
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
                "Concurrent access to a PKCS#11 Session is not supported. " +
                $"Method '{caller ?? "<unknown>"}' was invoked while another operation is in progress " +
                "on a different thread. Use a separate Session per thread.");
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
    /// outside it by <see cref="Enforce(PolicyRequest)"/>, so it is <see langword="volatile"/>.
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

    private void Enforce(Mechanism mechanism, CryptoOperation operation, IReadOnlyList<Objects.ObjectAttribute>? resultTemplate = null)
    {
        Enforce(new MechanismUseRequest(mechanism, operation));

        // The KDF an ECDH derivation or KEM applies to the shared secret is judged here, on every call
        // carrying CK_ECDH1_DERIVE_PARAMS, whichever public entry point it came through. Whether the
        // result is derivation-only is read off the template the token will receive, so a caller cannot
        // claim it.
        if (mechanism.Parameters is CkmEcdh1DeriveParams ecdh)
            Enforce(new KeyAgreementKdfRequest(mechanism.Type, ecdh.Kdf)
            {
                ResultIsDerivationOnlySecret = resultTemplate is not null && IsDerivationOnlySecret(resultTemplate),
            });
    }

    // See KeyAgreementKdfRequest.ResultIsDerivationOnlySecret. Every usage attribute must be present and
    // false: a token's default for an omitted one is its own choice. A template listing an attribute
    // twice must agree with itself on every occurrence.
    internal static bool IsDerivationOnlySecret(IReadOnlyList<Objects.ObjectAttribute> template)
    {
        bool All(CKA type, bool required, Func<Objects.ObjectAttribute, bool> holds)
        {
            Objects.ObjectAttribute[] occurrences = [.. template.Where(a => a.Type == type)];
            return occurrences.Length == 0 ? !required : occurrences.All(holds);
        }

        return All(CKA.CKA_CLASS, required: true, a => a.GetValueAsUlong() == (ulong)CKO.CKO_SECRET_KEY)
            && All(CKA.CKA_KEY_TYPE, required: true, a => a.GetValueAsUlong() == (ulong)CKK.CKK_GENERIC_SECRET)
            && All(CKA.CKA_DERIVE, required: true, a => a.GetValueAsBool())
            && All(CKA.CKA_ENCRYPT, required: true, a => !a.GetValueAsBool())
            && All(CKA.CKA_DECRYPT, required: true, a => !a.GetValueAsBool())
            && All(CKA.CKA_SIGN, required: true, a => !a.GetValueAsBool())
            && All(CKA.CKA_VERIFY, required: true, a => !a.GetValueAsBool())
            && All(CKA.CKA_WRAP, required: true, a => !a.GetValueAsBool())
            && All(CKA.CKA_UNWRAP, required: true, a => !a.GetValueAsBool())
            // Omitted is fine: BuildSecureKeyDefaults then sets CKA_SENSITIVE=true / CKA_EXTRACTABLE=false.
            && All(CKA.CKA_SENSITIVE, required: false, a => a.GetValueAsBool())
            && All(CKA.CKA_EXTRACTABLE, required: false, a => !a.GetValueAsBool());
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
    private sealed class PolicyLease(Pkcs11SessionCore session, ICryptoPolicy policy) : IDisposable
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
            CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, out CK_SESSION_INFO info);
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
    /// <param name="slotId">
    /// The slot the session was opened on. Required: <c>CKM_PKCS5_PBKD2</c> picks its parameter layout
    /// from it, and a session that sent NSS softoken before 3.114 the wrong one would crash the process.
    /// </param>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    /// <param name="loggerFactory">
    /// Logger factory inherited from the owning <see cref="Pkcs11Slot"/>/<see cref="Pkcs11Library"/>;
    /// <see langword="null"/> for no logging.
    /// </param>
    /// <param name="policy">
    /// The policy to enforce on this session; <see langword="null"/> means <see cref="CryptoPolicy.SecureOnly"/>.
    /// </param>
    internal Pkcs11SessionCore(LowLevelPkcs11Library pkcs11Library, NativeCULong slotId, ulong sessionId, ILoggerFactory? loggerFactory = null, ICryptoPolicy? policy = null)
        : this(pkcs11Library, slotId, OwnSession(pkcs11Library, sessionId), loggerFactory, policy)
    {
    }

    /// <summary>
    /// Takes ownership of an open session's <paramref name="sessionHandle"/>: if construction throws, the
    /// handle is disposed and the session closed, so it can never be left open with no owner.
    /// </summary>
    internal Pkcs11SessionCore(LowLevelPkcs11Library pkcs11Library, NativeCULong slotId, Pkcs11SessionHandle sessionHandle, ILoggerFactory? loggerFactory = null, ICryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(sessionHandle);
        _sessionHandle = sessionHandle;
        try
        {
            if (sessionHandle.IsInvalid)
                throw new ArgumentException("Invalid handle specified", nameof(sessionHandle));

            // Both run consumer code (the factory, the logger), which may throw.
            _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<Pkcs11SessionCore>();
            Log.SessionTrace(_logger, (ulong)sessionHandle.SessionId, "ctor");

            _basePolicy = policy ?? CryptoPolicy.SecureOnly;
            _effectivePolicy = _basePolicy;
            _pkcs11Library = pkcs11Library;
            _slotId = slotId;
        }
        catch
        {
            sessionHandle.Dispose();
            throw;
        }
    }

    private static Pkcs11SessionHandle OwnSession(LowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        ArgumentNullException.ThrowIfNull(pkcs11Library);
        if (sessionId == CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", nameof(sessionId));
        return new Pkcs11SessionHandle(pkcs11Library, (NativeCULong)sessionId);
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
    /// here rather than in <see cref="OperationScope"/>: a <see langword="using"/> struct local is read-only, so the
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
        private readonly Pkcs11SessionCore _session;
        private readonly string _name;

        // What was in progress before this scope: an operation begun by a caller re-entering on this
        // thread is that caller's to end.
        private readonly ulong _outer;

        internal OperationScope(Pkcs11SessionCore session, string name)
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

        /// <summary>
        /// Records that the verify call that finishes the operation returned <paramref name="rv"/>. Every
        /// code ends the operation (PKCS#11 v3.2 §5.2), but a module may leave it active after
        /// <c>CKR_SIGNATURE_LEN_RANGE</c> (Kryoptic does): that one is left to the cancel on disposal, which
        /// finds nothing to cancel on a module that ended it.
        /// </summary>
        public void CompletedVerify(CKR rv)
        {
            if (rv != CKR.CKR_SIGNATURE_LEN_RANGE)
                Completed();
        }

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
                Log.SessionCancelFailed(_logger, (ulong)_sessionId, operationName, rv);
                return;
        }
    }

    /// <summary>
    /// The logout an owning <see cref="Pkcs11Session"/> issues just before disposing this session.
    /// Waits for the busy lock instead of going through <see cref="AcquireExclusive"/>, for the
    /// reason <see cref="Dispose(bool)"/> does: it runs from a disposal, where throwing on
    /// cross-thread contention would leave the session open and replace any exception a
    /// surrounding <see langword="using"/> is unwinding. A session that is already disposed is left alone.
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
}
