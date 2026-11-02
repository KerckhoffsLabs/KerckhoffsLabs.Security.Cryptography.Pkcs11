using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// The read-back in progress on this session, or <see langword="null"/>. Set and cleared only by
    /// <see cref="BeginReadBack"/> and <see cref="ReadBackGrant.Dispose"/>, by the thread holding the session's
    /// exclusive lease for the grant's whole life, so no other thread can run an operation it would tag.
    /// </summary>
    private ReadBackGrant? _readBack;

    /// <summary>
    /// The policies this session has warned about an export under, each with the kinds (one bit per
    /// <see cref="KeyMaterialExportKind"/>) already reported. Weak keys: a session that cycles through
    /// short-lived policies does not keep them alive. Mutated only under the exclusive lease.
    /// </summary>
    private readonly ConditionalWeakTable<ICryptoPolicy, StrongBox<int>> _exportsWarned = [];

    /// <summary>
    /// The kind a <see cref="KeyTemplateRequest"/> or <see cref="KeyAgreementKdfRequest"/> raised now is a
    /// read-back of (<see cref="KeyTemplateRequest.ReadBackFor"/>), or <see langword="null"/>. The only source of
    /// the tag, and deliberately narrow: the open grant's kind only while it is armed (inside the library call that
    /// creates the ephemeral key, <see cref="ReadBackGrant.Create{T}"/>), only on the thread that holds it, and
    /// never while caller code runs on that thread (<see cref="CallOutScope"/>). The session lock is reentrant, so
    /// without the last two a logger sink or a custom policy calling back into the session from inside the
    /// read-back would have its own templates judged as the library's read-back.
    /// </summary>
    private KeyMaterialExportKind? ReadBackKind =>
        _readBack is { Armed: true } grant
        && grant.OwnerThreadId == Environment.CurrentManagedThreadId
        && !CallOutScope.Active
            ? grant.Kind
            : null;

    /// <summary>
    /// Asks the policy whether <paramref name="kind"/> may be read off the token and, if so, opens a
    /// read-back of it: the session is held exclusively until the grant is disposed, and the key templates
    /// and key-agreement KDFs the session judges inside <see cref="ReadBackGrant.Create{T}"/> are tagged as a
    /// read-back of <paramref name="kind"/>. This is the one place a read-back is authorized: no other path
    /// sets the tag.
    /// </summary>
    /// <remarks>
    /// The policy is asked once, under the session lock. If the lock is busy (another thread is using the
    /// session), the policy is asked before the contention is reported, so a refused export surfaces as the
    /// <see cref="CryptoPolicyViolationException"/> callers rely on whatever the session is doing; only an
    /// allowed one reports the contention.
    /// </remarks>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the export.</exception>
    /// <exception cref="InvalidOperationException">Another thread is using the session, or a read-back is already open on it.</exception>
    internal ReadBackGrant BeginReadBack(KeyMaterialExportKind kind)
    {
        var request = new KeyMaterialExportRequest(kind);
        ExclusiveLease lease;
        try
        {
            lease = AcquireExclusive();
        }
        catch (InvalidOperationException)
        {
            // Contention: the refusal, if there is one, is the answer the caller acts on.
            EnforceUnder(request);
            throw;
        }

        try
        {
            if (_readBack is not null)
                throw new InvalidOperationException("A secret read-back is already in progress on this session.");

            ICryptoPolicy policy = EnforceUnder(request);
            var grant = new ReadBackGrant(this, lease, kind, policy);
            _readBack = grant;
            return grant;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    // Warning the first time a policy lets this session read a kind; Debug every later time. Names the kind and
    // the policy only, never the bytes. Called once the value has been read and checked, so it reports
    // exports that happened, not ones a later check or the token refused.
    private void LogExport(ICryptoPolicy policy, KeyMaterialExportKind kind)
    {
        StrongBox<int> warned = _exportsWarned.GetValue(policy, static _ => new StrongBox<int>());
        int bit = 1 << (int)kind;
        if ((warned.Value & bit) == 0)
        {
            warned.Value |= bit;
            Log.KeyMaterialExportAllowed(_logger, (ulong)_sessionId, policy.Name, kind);
        }
        else
        {
            Log.KeyMaterialExported(_logger, (ulong)_sessionId, policy.Name, kind);
        }
    }

    /// <summary>
    /// An open read-back: the policy allowed <see cref="Kind"/> to be read off the token, and the session is
    /// held exclusively until <see cref="Dispose"/>. The façade's <see cref="KeyMaterial.SecretReadBack"/> runs the read
    /// itself; this is the session's half, which holds the tag and the lease.
    /// </summary>
    internal sealed class ReadBackGrant : KeyMaterial.IReadBackGrant
    {
        private readonly Pkcs11SessionCore _core;
        private readonly ExclusiveLease _lease;
        private readonly ICryptoPolicy _policy;
        private bool _disposed;

        internal ReadBackGrant(Pkcs11SessionCore core, ExclusiveLease lease, KeyMaterialExportKind kind, ICryptoPolicy policy)
        {
            _core = core;
            _lease = lease;
            _policy = policy;
            Kind = kind;
            OwnerThreadId = Environment.CurrentManagedThreadId;
        }

        /// <summary>The kind of secret the policy allowed to be read.</summary>
        internal KeyMaterialExportKind Kind { get; }

        /// <summary>The thread that opened the grant and holds the session's lease.</summary>
        internal int OwnerThreadId { get; }

        /// <summary>Whether <see cref="Create{T}"/> is running: the only time the session tags a request.</summary>
        internal bool Armed { get; private set; }

        /// <summary>
        /// Runs <paramref name="createEphemeral"/>, the library call that creates the key the secret is read
        /// from, with the grant armed: the templates and key-agreement KDFs it submits are judged as this
        /// read-back. Nothing outside it is tagged, the read, the checks and the export report included.
        /// </summary>
        public T Create<T>(Func<T> createEphemeral)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (Environment.CurrentManagedThreadId != OwnerThreadId)
                throw new InvalidOperationException("A secret read-back must be completed on the thread that opened it.");
            if (Armed)
                throw new InvalidOperationException("A secret read-back's ephemeral key is already being created.");
            Armed = true;
            try
            {
                return createEphemeral();
            }
            finally
            {
                Armed = false;
            }
        }

        /// <summary>
        /// Reports the export, once the value has been read and checked: <see cref="KeyMaterial.SecretReadBack.Read"/> calls
        /// it last, so a read-back the token or a later check stops reports nothing.
        /// </summary>
        public void ReportExport()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _core.LogExport(_policy, Kind);
        }

        /// <summary>Closes the read-back and releases the session.</summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Armed = false;
            _core._readBack = null;
            _lease.Dispose();
        }
    }

    /// <summary>
    /// Marks the current thread as running caller code on the library's behalf: a policy's
    /// <see cref="ICryptoPolicy.Evaluate"/> or a logger sink. While one is active, nothing the session judges
    /// on this thread is tagged as a read-back (<see cref="ReadBackKind"/>). Thread-static, so it covers a call
    /// back into any session, and nests.
    /// </summary>
    internal readonly struct CallOutScope : IDisposable
    {
        [ThreadStatic]
        private static int t_depth;

        /// <summary>Whether caller code is running on this thread inside a call-out.</summary>
        internal static bool Active => t_depth > 0;

        /// <summary>Opens a call-out on this thread; dispose it when the caller's code returns.</summary>
        internal static CallOutScope Enter()
        {
            t_depth++;
            return default;
        }

        public void Dispose() => t_depth--;
    }
}
