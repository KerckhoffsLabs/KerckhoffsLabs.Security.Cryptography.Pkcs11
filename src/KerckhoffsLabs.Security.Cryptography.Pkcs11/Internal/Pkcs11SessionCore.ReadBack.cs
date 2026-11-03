using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// The read-back in progress on this session, or <see langword="null"/>. Set and cleared only by
    /// <see cref="BeginReadBack"/> and <see cref="ReadBackGrant.Dispose"/>. A request is tagged only when the
    /// operation raising it was handed this grant (<see cref="ReadBackExport"/>).
    /// </summary>
    private ReadBackGrant? _readBack;

    /// <summary>
    /// The policies this session has warned about an export under, each with the kinds (one bit per
    /// <see cref="KeyMaterialExportKind"/>) already reported. Weak keys: a session that cycles through
    /// short-lived policies does not keep them alive. Mutated only under the exclusive lease.
    /// </summary>
    private readonly ConditionalWeakTable<ICryptoPolicy, StrongBox<int>> _exportsWarned = [];

    /// <summary>
    /// The export a <see cref="KeyTemplateRequest"/> or <see cref="KeyAgreementKdfRequest"/> is a read-back of
    /// (<see cref="KeyTemplateRequest.ReadBackFor"/>), as the policy allowed it, or <see langword="null"/> when
    /// <paramref name="readBack"/> is. The only source of the tag, and explicit: only a request the library raised
    /// with the open grant in hand is tagged. Code that calls back into the session from inside a read-back (a
    /// logger sink, a custom policy) has no grant, so its requests are judged as the caller's.
    /// </summary>
    /// <exception cref="InvalidOperationException"><paramref name="readBack"/> is not the read-back open on this session.</exception>
    private KeyMaterialExportRequest? ReadBackExport(KeyMaterial.IReadBackGrant? readBack)
    {
        if (readBack is null)
            return null;
        if (readBack is not ReadBackGrant grant || !ReferenceEquals(grant, _readBack))
            throw new InvalidOperationException("The secret read-back is not open on this session.");
        return grant.Request;
    }

    /// <summary>
    /// Asks the policy whether <paramref name="kind"/> may be read off the token and, if so, opens a
    /// read-back of it: the session is held exclusively until the grant is disposed, and the key templates
    /// and key-agreement KDFs of the operations the grant is passed to are tagged as a read-back of
    /// <paramref name="kind"/>. This is the one place a read-back is authorized: no other path makes a grant.
    /// </summary>
    /// <remarks>
    /// The policy is asked once, under the session lock, with what <paramref name="readSourceKey"/> read off the key
    /// the secret comes from: the KDF's base key for <see cref="KeyMaterialExportKind.KdfOutput"/>
    /// (<see cref="KeyMaterialExportRequest.KdfBaseKey"/>), the private key otherwise
    /// (<see cref="KeyMaterialExportRequest.PrivateKey"/>). If the lock is busy (another thread is
    /// using the session), the policy is first asked about the kind alone, so a kind it refuses surfaces as the
    /// <see cref="CryptoPolicyViolationException"/> callers rely on whatever the session is doing; otherwise the
    /// contention is reported, as the key cannot be read without the lock.
    /// </remarks>
    /// <param name="kind">The kind of secret to read.</param>
    /// <param name="readSourceKey">
    /// Reads the attributes of the key the secret comes from (under the lock, on this thread): the KDF's base key, or
    /// the private key of an agreement or decapsulation. <see langword="null"/> for a KDF with no base key (PBKDF2) and
    /// for a KEM encapsulation.
    /// </param>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the export.</exception>
    /// <exception cref="InvalidOperationException">Another thread is using the session, or a read-back is already open on it.</exception>
    internal ReadBackGrant BeginReadBack(KeyMaterialExportKind kind, Func<ExportKeyInfo>? readSourceKey = null)
    {
        ExclusiveLease lease;
        try
        {
            lease = AcquireExclusive();
        }
        catch (InvalidOperationException)
        {
            // Contention: a refusal of the kind itself is the answer the caller acts on. No key in the request
            // means no key scope to fail, so this verdict is the kind's alone.
            EnforceUnder(new KeyMaterialExportRequest(kind));
            throw;
        }

        try
        {
            if (_readBack is not null)
                throw new InvalidOperationException("A secret read-back is already in progress on this session.");

            ExportKeyInfo? sourceKey = readSourceKey?.Invoke();
            var request = kind == KeyMaterialExportKind.KdfOutput
                ? new KeyMaterialExportRequest(kind) { KdfBaseKey = sourceKey }
                : new KeyMaterialExportRequest(kind) { PrivateKey = sourceKey };
            ICryptoPolicy policy = EnforceUnder(request);
            var grant = new ReadBackGrant(this, lease, request, policy);
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
    /// itself, passing this grant to the operation that creates the ephemeral key; this is the session's half, which
    /// holds the allowed export and the lease.
    /// </summary>
    internal sealed class ReadBackGrant : KeyMaterial.IReadBackGrant
    {
        private readonly Pkcs11SessionCore _core;
        private readonly ExclusiveLease _lease;
        private readonly ICryptoPolicy _policy;
        private bool _disposed;

        internal ReadBackGrant(Pkcs11SessionCore core, ExclusiveLease lease, KeyMaterialExportRequest request, ICryptoPolicy policy)
        {
            _core = core;
            _lease = lease;
            _policy = policy;
            Request = request;
        }

        /// <summary>The export the policy allowed, key info included.</summary>
        internal KeyMaterialExportRequest Request { get; }

        /// <summary>The kind of secret the policy allowed to be read.</summary>
        internal KeyMaterialExportKind Kind => Request.Kind;

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
            _core._readBack = null;
            _lease.Dispose();
        }
    }
}
