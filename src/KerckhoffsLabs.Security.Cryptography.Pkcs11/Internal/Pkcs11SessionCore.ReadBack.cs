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
    /// read-back of (<see cref="KeyTemplateRequest.ReadBackFor"/>): the open grant's kind on the thread that
    /// holds it, <see langword="null"/> everywhere else. The only source of the tag.
    /// </summary>
    private KeyMaterialExportKind? ReadBackKind =>
        _readBack is { } grant && grant.OwnerThreadId == Environment.CurrentManagedThreadId ? grant.Kind : null;

    /// <summary>
    /// Asks the policy whether <paramref name="kind"/> may be read off the token and, if so, opens a
    /// read-back of it: the session is held exclusively until the grant is disposed, and every key template
    /// and key-agreement KDF the session judges meanwhile is tagged as a read-back of
    /// <paramref name="kind"/>. This is the one place a read-back is authorized: no other path sets the tag.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the export.</exception>
    /// <exception cref="InvalidOperationException">Another thread is using the session, or a read-back is already open on it.</exception>
    internal ReadBackGrant BeginReadBack(KeyMaterialExportKind kind)
    {
        ExclusiveLease lease = AcquireExclusive();
        try
        {
            if (_readBack is not null)
                throw new InvalidOperationException("A secret read-back is already in progress on this session.");

            ICryptoPolicy policy = EnforceUnder(new KeyMaterialExportRequest(kind));
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
    internal sealed class ReadBackGrant : IDisposable
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

        /// <summary>
        /// Reports the export, once the value has been read and checked: <see cref="KeyMaterial.SecretReadBack.Read"/> calls
        /// it last, so a read-back the token or a later check stops reports nothing.
        /// </summary>
        internal void ReportExport()
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
