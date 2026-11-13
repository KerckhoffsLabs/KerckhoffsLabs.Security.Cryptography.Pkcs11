using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A PKCS#11 session with a token (<c>CK_SESSION_HANDLE</c>), and the operations a caller performs
/// through it: key lookup, generation, import, RNG access, and one-shot digests.
/// </summary>
/// <remarks>
/// <para>
/// Opened by <see cref="Pkcs11Login.OpenSession"/>, a session that keeps that login while it is open, or by
/// <see cref="Pkcs11Slot.OpenSession"/>, one that keeps none but sees whatever login the application has on
/// the token (PKCS#11 login state belongs to the application and the token, not to a session). The session
/// does not own the library — callers continue to own and dispose the <see cref="Pkcs11Library"/>.
/// <see cref="Dispose"/> closes the session (<c>C_CloseSession</c>) and never logs out: the last holder of
/// the login does (see <see cref="Pkcs11Login"/>).
/// </para>
/// <para>
/// Keys obtained via the session's factory methods hold a non-owning reference to the
/// session. The session must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Session : IDisposable
{
    private readonly Pkcs11SessionCore _core;

    // This session's hold of Login, released once the session is closed; null for a slot session.
    private readonly LoginHold? _hold;
    private bool _disposed;

    internal Pkcs11Session(Pkcs11Library library, Pkcs11Slot slot, Pkcs11SessionCore core,
        SessionAccess access = SessionAccess.ReadWrite, Pkcs11Login? login = null, LoginHold? hold = null)
    {
        Library = library;
        Slot = slot;
        _core = core;
        Access = access;
        Login = login;
        _hold = hold;
    }

    /// <summary>The slot this session is open on.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>Whether this session may change the token: read-only or read/write.</summary>
    public SessionAccess Access { get; }

    /// <summary>
    /// The login this session was opened through and keeps while open (<see cref="Pkcs11Login.OpenSession"/>),
    /// or <see langword="null"/> for a session from <see cref="Pkcs11Slot.OpenSession"/>, which keeps none.
    /// <see cref="GetSessionInfo"/> gives the module's own answer on the session's state.
    /// </summary>
    public Pkcs11Login? Login { get; }

    /// <summary>The library that hosts this session. The session does not own the library.</summary>
    public Pkcs11Library Library { get; }

    /// <summary>The session's native calls and policy enforcement. Used by <c>Pkcs11Key</c> to delegate operations.</summary>
    internal Pkcs11SessionCore Core => _core;

    /// <summary>
    /// Submits <paramref name="request"/> to the session's effective <see cref="Policy"/>, as every operation
    /// of this library does before it reaches the token, and throws if the policy refuses it. A refusal is
    /// logged, as for a refused operation.
    /// </summary>
    /// <remarks>
    /// For work done off the token on the session's behalf, which no session or key method sees: an
    /// adapter that hashes in managed code before signing on the token checks the hash with a
    /// <see cref="HashUseRequest"/> here first. Operations of this library check their own requests; a
    /// request it allows here grants nothing to them.
    /// </remarks>
    /// <param name="request">The request to judge.</param>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses <paramref name="request"/>.</exception>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    public void EnforcePolicy(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);
        _core.Enforce(request);
    }

    /// <summary>
    /// Opens a read-back of <paramref name="kind"/> once the policy allows it; see <see cref="SecretReadBack"/>.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the export.</exception>
    /// <exception cref="InvalidOperationException">Another thread is using the session, or a read-back is already open on it.</exception>
    /// <param name="kind">The kind of secret to read.</param>
    /// <param name="sourceKey">
    /// The key the secret comes from, whose attributes the policy's scope for <paramref name="kind"/> judges: for
    /// <see cref="KeyMaterialExportKind.KdfOutput"/> the KDF's base key (<see cref="KeyMaterialExportRequest.KdfBaseKey"/>),
    /// otherwise the agreement's or decapsulation's private key (<see cref="KeyMaterialExportRequest.PrivateKey"/>).
    /// <see langword="null"/> for a KDF with no base key (PBKDF2) and for a KEM encapsulation.
    /// </param>
    internal SecretReadBack BeginReadBack(KeyMaterialExportKind kind, Pkcs11Key? sourceKey = null)
        => new(_core.BeginReadBack(kind, sourceKey is null ? null : sourceKey.ReadExportKeyInfo));

    /// <summary>
    /// Whether the session's effective <see cref="Policy"/> allows <paramref name="request"/>; unlike
    /// <see cref="EnforcePolicy"/>, it neither throws on a refusal nor logs it.
    /// </summary>
    /// <param name="request">The request to judge.</param>
    /// <returns><see langword="true"/> if the policy allows <paramref name="request"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    public bool IsAllowedByPolicy(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _core.IsPermitted(request);
    }

    /// <summary>
    /// The crypto policy currently enforced by this session: the one it was opened with, unless a
    /// <see cref="UsePolicy"/> lease is active.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    public ICryptoPolicy Policy
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _core.Policy;
        }
    }

    /// <summary>
    /// Enforces <paramref name="policy"/> until the returned lease is disposed. Logged as a warning. Scope it to the operation that needs it:
    /// <code>
    /// using (session.UsePolicy(CryptoPolicy.AllowInsecure)) { /* one legacy operation */ }
    /// </code>
    /// Open leases form a stack: the most recently opened lease still open decides the policy, and the
    /// session's own policy applies once none is open. Disposing a lease withdraws only that lease, so
    /// disposing them out of order never re-instates a policy whose lease is already closed. The override
    /// applies to the whole session, not per thread.
    /// </summary>
    /// <param name="policy">The policy to enforce within the lease.</param>
    /// <returns>A lease that withdraws this override when disposed (idempotent).</returns>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The session was opened under a policy whose
    /// <see cref="ICryptoPolicy.AllowsOverride"/> is false (for example <c>CryptoPolicy.NistApproved</c>).</exception>
    public IDisposable UsePolicy(ICryptoPolicy policy)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _core.UsePolicy(policy);
    }

    /// <summary>
    /// Returns a snapshot of the session's state (slot, session state, flags, and the
    /// device-specific error code), as reported by <c>C_GetSessionInfo</c>.
    /// </summary>
    /// <returns>A <see cref="SessionInfo"/> describing the current session.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if the underlying <c>C_GetSessionInfo</c> call fails.</exception>
    public SessionInfo GetSessionInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _core.GetSessionInfo();
    }

    /// <summary>
    /// Closes the session (<c>C_CloseSession</c>), waiting for an operation in flight on it, and then
    /// releases its hold of <see cref="Login"/>, if any. Never sends <c>C_Logout</c> itself: when this was the
    /// last holder of the login, releasing the hold logs out. Idempotent.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Called from inside an operation on the same token, for a session that holds a login: the logout its
    /// release may send waits for operations to finish, so it cannot run from one. Nothing is closed then.
    /// </exception>
    public void Dispose()
    {
        if (_disposed) return;

        // Refused before anything changes: once the session is closed its hold could no longer be released.
        _hold?.Record.ThrowIfInsideOperation();

        // The close waits for this session's operation lease, so the hold is released after it, outside any
        // operation, and the logout the last holder sends can take the login's gate.
        _core.Dispose();
        _disposed = true;
        _hold?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_LABEL</c> is <paramref name="label"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only key objects match — certificates and data objects that share the label are ignored. The
    /// lookup must identify exactly one key; anything more is refused with
    /// <see cref="Pkcs11AmbiguousObjectException"/> rather than resolved by picking a match, which would
    /// let whoever can create objects on the token decide which key an operation uses. Narrow an
    /// ambiguous lookup with <see cref="OpenKey(ObjectTemplate)"/> (by key class, key type or any other
    /// attribute), or by <c>CKA_ID</c>.
    /// </para>
    /// <para>
    /// The private and public halves of a pair (same <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c>) count as one
    /// key. When only one half matched, the other is found by <c>CKA_ID</c> the first time an operation
    /// on the key needs it, not here; if that lookup fails, the error comes from that operation
    /// (<c>Verify</c>, <c>Encrypt</c>, <c>Sign</c>, <c>GetAttributeValue</c>, …), and the next use looks
    /// again. Halves with an empty <c>CKA_ID</c> can only be paired when both matched the lookup.
    /// </para>
    /// </remarks>
    /// <param name="label">The <c>CKA_LABEL</c> to match.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no key matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Key OpenKey(string label)
    {
        ArgumentNullException.ThrowIfNull(label);
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return OpenKeyCore(filter, $"with label '{label}'");
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_ID</c> is <paramref name="id"/>. See <see cref="OpenKey(string)"/>
    /// for which objects match and when the lookup is ambiguous.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no key matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Key OpenKey(ReadOnlySpan<byte> id)
    {
        if (id.IsEmpty) throw new ArgumentException(EmptyIdMessage, nameof(id));
        using var filter = ObjectTemplate.Empty().Id(id).Build();
        return OpenKeyCore(filter, $"with CKA_ID ({id.Length} bytes)");
    }

    /// <summary>
    /// Opens the one key that matches <paramref name="filter"/>: any attributes, such as a key class
    /// (<c>CKA_CLASS = CKO_SECRET_KEY</c>) or a key type (<c>CKA_KEY_TYPE = CKK_EC</c>) next to a label.
    /// See <see cref="OpenKey(string)"/> for which objects match and when the lookup is ambiguous.
    /// </summary>
    /// <remarks>
    /// Without a <c>CKA_CLASS</c>, private, public and secret keys are all searched. A <c>CKA_CLASS</c>
    /// in the filter must be one of those three.
    /// </remarks>
    /// <param name="filter">The attributes to match. Use an <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names a <c>CKA_CLASS</c> that is not a key class.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no key matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Key OpenKey(ObjectTemplate filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return OpenKeyCore(filter, "matching the filter");
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_LABEL</c> is <paramref name="label"/>, or reports that there is
    /// none. Matches exactly as <see cref="OpenKey(string)"/> does.
    /// </summary>
    /// <remarks>
    /// Only "no match" returns <see langword="false"/>. Several matches still throw
    /// <see cref="Pkcs11AmbiguousObjectException"/>: that is a problem with the token's contents, not
    /// an absent key.
    /// </remarks>
    /// <param name="label">The <c>CKA_LABEL</c> to match.</param>
    /// <param name="key">The key, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one key matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenKey(string label, [NotNullWhen(true)] out Pkcs11Key? key)
    {
        ArgumentNullException.ThrowIfNull(label);
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        key = FindUniqueKey(filter);
        return key is not null;
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_ID</c> is <paramref name="id"/>, or reports that there is none.
    /// Matches exactly as <see cref="OpenKey(ReadOnlySpan{byte})"/> does; see
    /// <see cref="TryOpenKey(string, out Pkcs11Key?)"/> for what returns <see langword="false"/>.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <param name="key">The key, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one key matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenKey(ReadOnlySpan<byte> id, [NotNullWhen(true)] out Pkcs11Key? key)
    {
        if (id.IsEmpty) throw new ArgumentException(EmptyIdMessage, nameof(id));
        using var filter = ObjectTemplate.Empty().Id(id).Build();
        key = FindUniqueKey(filter);
        return key is not null;
    }

    /// <summary>
    /// Opens the one key that matches <paramref name="filter"/>, or reports that there is none. Matches
    /// exactly as <see cref="OpenKey(ObjectTemplate)"/> does; see
    /// <see cref="TryOpenKey(string, out Pkcs11Key?)"/> for what returns <see langword="false"/>.
    /// </summary>
    /// <param name="filter">The attributes to match. Use an <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <param name="key">The key, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one key matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names a <c>CKA_CLASS</c> that is not a key class.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if the matches form more than one key.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenKey(ObjectTemplate filter, [NotNullWhen(true)] out Pkcs11Key? key)
    {
        ArgumentNullException.ThrowIfNull(filter);
        key = FindUniqueKey(filter);
        return key is not null;
    }

    /// <summary>
    /// Finds all keys matching the given template.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only private, public and secret keys are returned, as for <see cref="OpenKey(ObjectTemplate)"/>: a
    /// certificate or data object that matches the filter (a certificate shares its key's <c>CKA_ID</c>) is
    /// left out. A <c>CKA_CLASS</c> in the filter must be one of the three key classes. The search is still
    /// one <c>C_FindObjects</c> pass and one attribute read per object found.
    /// </para>
    /// <para>
    /// The other half of a key pair (same <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c>) is looked up the first
    /// time an operation on the key needs it, not here. If that lookup fails, the error comes from that
    /// operation (<c>Verify</c>, <c>Encrypt</c>, <c>Sign</c>, <c>GetAttributeValue</c>, …), and the
    /// next use looks again.
    /// </para>
    /// </remarks>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A list of <see cref="Pkcs11Key"/>. May be empty. The list owns the keys: dispose it
    /// (a <see langword="using"/> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names a <c>CKA_CLASS</c> that is not a key class.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Key> FindKeys(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        _ = ClassesToSearch(filter, Keys); // refuses a CKA_CLASS that is not a key class

        // The search and the reads that wrap each key run under one lease, which holds the login gate: a private
        // key is tied to the login state the search ran under.
        using var lease = _core.AcquireExclusive();

        // One search, not one per key class: the class comes with the attribute read each found object
        // gets anyway, and objects of other classes are dropped there.
        var handles = _core.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Key>(handles.Count);
        foreach (var handle in handles)
        {
            if (HydrateKeyFromHandle(handle, keysOnly: true) is { } key)
                result.Add(key);
        }
        return new ReadOnlyDisposableList<Pkcs11Key>(result);
    }

    /// <summary>
    /// Finds all token objects matching the given template, regardless of class — certificates,
    /// data objects, keys, etc. Unlike <see cref="FindKeys"/> (which is key-only and reads
    /// <c>CKA_KEY_TYPE</c>), this returns a general <see cref="Pkcs11Object"/> view exposing the
    /// object class and its <c>CKA_VALUE</c>.
    /// </summary>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder
    /// (e.g. filter on <c>CKA_CLASS = CKO_CERTIFICATE</c>).</param>
    /// <returns>A list of <see cref="Pkcs11Object"/>. May be empty. The list owns the objects: dispose
    /// it (a <see langword="using"/> will do) to release them all. Disposal does not destroy anything on the token.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Object> FindObjects(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        using var lease = _core.AcquireExclusive(); // see FindKeys
        var handles = _core.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Object>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateObjectFromHandle(handle));
        return new ReadOnlyDisposableList<Pkcs11Object>(result);
    }

    /// <summary>
    /// Opens the one object that matches <paramref name="filter"/>: a data object, a profile, or any other
    /// class that is neither a key nor a certificate. The filter must name the class, e.g.
    /// <c>ObjectTemplate.ForData().Label("config")</c>.
    /// </summary>
    /// <remarks>
    /// The lookup rules are those of <see cref="OpenKey(string)"/>: exactly one object must match, and
    /// several are refused with <see cref="Pkcs11AmbiguousObjectException"/> rather than resolved by
    /// picking one. Keys and certificates have their own typed lookups and are refused here, so a filter
    /// mistake can't return a key as a generic object.
    /// </remarks>
    /// <param name="filter">The attributes to match, including <c>CKA_CLASS</c>.</param>
    /// <returns>A new <see cref="Pkcs11Object"/>. Disposing it never destroys the token object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="filter"/> names no <c>CKA_CLASS</c>, or a key or certificate class: open those
    /// with <see cref="OpenKey(ObjectTemplate)"/> or <see cref="OpenCertificate(ObjectTemplate)"/>.
    /// </exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no object matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one object matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Object OpenObject(ObjectTemplate filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ObjectFamily family = OtherObjects(filter);
        return FindUniqueObject(filter, family)
            ?? throw new Pkcs11ObjectNotFoundException(Pkcs11Operations.OpFindObjects, $"No {family.Name} matching the filter was found on the token.");
    }

    /// <summary>
    /// Opens the one object that matches <paramref name="filter"/>, or reports that there is none. Matches
    /// exactly as <see cref="OpenObject(ObjectTemplate)"/> does.
    /// </summary>
    /// <remarks>
    /// Only "no match" returns <see langword="false"/>. Several matches still throw
    /// <see cref="Pkcs11AmbiguousObjectException"/>.
    /// </remarks>
    /// <param name="filter">The attributes to match, including <c>CKA_CLASS</c>.</param>
    /// <param name="obj">The object, when one matched.</param>
    /// <returns><see langword="true"/> if exactly one object matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="filter"/> names no <c>CKA_CLASS</c>, or a key or certificate class: open those
    /// with <see cref="OpenKey(ObjectTemplate)"/> or <see cref="OpenCertificate(ObjectTemplate)"/>.
    /// </exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one object matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenObject(ObjectTemplate filter, [NotNullWhen(true)] out Pkcs11Object? obj)
    {
        ArgumentNullException.ThrowIfNull(filter);
        obj = FindUniqueObject(filter, OtherObjects(filter));
        return obj is not null;
    }

    /// <summary>
    /// Creates an object on the token from <paramref name="template"/> — a data object
    /// (<see cref="ObjectTemplate.ForData"/>), a certificate of any type
    /// (<see cref="ObjectTemplate.ForCertificate"/>), or another non-key class — and returns it.
    /// </summary>
    /// <remarks>
    /// Keys are refused: import them with <see cref="ImportKey"/>, which applies the secure key defaults
    /// and returns a usable <see cref="Pkcs11Key"/>. For an X.509 certificate,
    /// <see cref="ImportCertificate"/> returns a typed <see cref="Pkcs11Certificate"/> instead.
    /// </remarks>
    /// <param name="template">A fully built template naming the object's <c>CKA_CLASS</c>.</param>
    /// <returns>The created object. Disposing it never destroys the token object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="template"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="template"/> names no <c>CKA_CLASS</c>, or a key class.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_CreateObject</c> call.</exception>
    public Pkcs11Object CreateObject(ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(template);

        ObjectAttribute named = template.Attributes.FirstOrDefault(a => a.Type == CKA.CKA_CLASS)
            ?? throw new ArgumentException("The template must name the object's CKA_CLASS.", nameof(template));
        var objectClass = (CKO)named.GetValueAsUlong();
        if (Array.IndexOf(Keys.Classes, objectClass) >= 0)
            throw new ArgumentException($"{objectClass} is a key class: import keys with ImportKey.", nameof(template));

        using var lease = _core.AcquireExclusive(); // see FindKeys
        ObjectHandle handle = _core.CreateObject([.. template.Attributes]);
        return HydrateObjectFromHandle(handle);
    }

    /// <summary>
    /// Finds all X.509 certificate objects on the token (<c>CKA_CLASS = CKO_CERTIFICATE</c>,
    /// <c>CKA_CERTIFICATE_TYPE = CKC_X_509</c>) — a typed counterpart to <see cref="FindKeys"/>. Each
    /// <see cref="Pkcs11Certificate"/> exposes the parsed <see cref="X509Certificate2"/> and bridges to
    /// its on-token private key by <c>CKA_ID</c>.
    /// </summary>
    /// <returns>A list of <see cref="Pkcs11Certificate"/>. May be empty. The list owns the certificates:
    /// dispose it (a <see langword="using"/> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if a certificate's
    /// <c>CKA_VALUE</c> cannot be read; also propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Certificate> FindCertificates()
    {
        using var filter = ObjectTemplate.Empty().Build();
        return FindCertificates(filter);
    }

    /// <summary>
    /// Finds the X.509 certificate objects that match <paramref name="filter"/>, which is applied on the
    /// token: only the matching certificates are read and parsed.
    /// </summary>
    /// <remarks>
    /// <c>CKA_CLASS = CKO_CERTIFICATE</c> and <c>CKA_CERTIFICATE_TYPE = CKC_X_509</c> are added unless the
    /// filter already names them, with those values.
    /// </remarks>
    /// <param name="filter">The attributes to match. Use an <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A list of <see cref="Pkcs11Certificate"/>. May be empty. The list owns the certificates:
    /// dispose it (a <see langword="using"/> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names another class or certificate type.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if a certificate's
    /// <c>CKA_VALUE</c> cannot be read; also propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Certificate> FindCertificates(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        // The search and the reads that wrap each certificate run under one lease, which holds the login gate: a
        // private certificate is tied to the login state the search ran under (see FindKeys).
        using var lease = _core.AcquireExclusive();
        var result = new List<Pkcs11Certificate>();
        try
        {
            foreach ((ObjectHandle handle, _) in SearchFamily(filter, Certificates))
                result.Add(HydrateCertificateFromHandle(handle));
        }
        catch
        {
            // A certificate that failed to read must not leave the ones already built undisposed.
            foreach (Pkcs11Certificate certificate in result)
                certificate.Dispose();
            throw;
        }
        return new ReadOnlyDisposableList<Pkcs11Certificate>(result);
    }

    /// <summary>
    /// Opens the one X.509 certificate whose <c>CKA_LABEL</c> is <paramref name="label"/>.
    /// </summary>
    /// <remarks>
    /// Only X.509 certificate objects match — keys and data objects that share the label are ignored.
    /// The lookup must identify exactly one certificate; several are refused with
    /// <see cref="Pkcs11AmbiguousObjectException"/> rather than resolved by picking one. Narrow an
    /// ambiguous lookup with <see cref="OpenCertificate(ObjectTemplate)"/> or by <c>CKA_ID</c>.
    /// </remarks>
    /// <param name="label">The <c>CKA_LABEL</c> to match.</param>
    /// <returns>A new <see cref="Pkcs11Certificate"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no certificate matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Certificate OpenCertificate(string label)
    {
        ArgumentNullException.ThrowIfNull(label);
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return OpenCertificateCore(filter, $"with label '{label}'");
    }

    /// <summary>
    /// Opens the one X.509 certificate whose <c>CKA_ID</c> is <paramref name="id"/>: the certificate of the
    /// key with that id. See <see cref="OpenCertificate(string)"/> for which objects match.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <returns>A new <see cref="Pkcs11Certificate"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no certificate matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Certificate OpenCertificate(ReadOnlySpan<byte> id)
    {
        if (id.IsEmpty) throw new ArgumentException(EmptyIdMessage, nameof(id));
        using var filter = ObjectTemplate.Empty().Id(id).Build();
        return OpenCertificateCore(filter, $"with CKA_ID ({id.Length} bytes)");
    }

    /// <summary>
    /// Opens the one X.509 certificate that matches <paramref name="filter"/>. See
    /// <see cref="OpenCertificate(string)"/> for which objects match, and
    /// <see cref="FindCertificates(ObjectTemplate)"/> for what the filter may name.
    /// </summary>
    /// <param name="filter">The attributes to match. Use an <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A new <see cref="Pkcs11Certificate"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names another class or certificate type.</exception>
    /// <exception cref="Pkcs11ObjectNotFoundException">Thrown if no certificate matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Certificate OpenCertificate(ObjectTemplate filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return OpenCertificateCore(filter, "matching the filter");
    }

    /// <summary>
    /// Opens the one X.509 certificate whose <c>CKA_LABEL</c> is <paramref name="label"/>, or reports that
    /// there is none. Matches exactly as <see cref="OpenCertificate(string)"/> does.
    /// </summary>
    /// <remarks>
    /// Only "no match" returns <see langword="false"/>. Several matches still throw
    /// <see cref="Pkcs11AmbiguousObjectException"/>.
    /// </remarks>
    /// <param name="label">The <c>CKA_LABEL</c> to match.</param>
    /// <param name="certificate">The certificate, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one certificate matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenCertificate(string label, [NotNullWhen(true)] out Pkcs11Certificate? certificate)
    {
        ArgumentNullException.ThrowIfNull(label);
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        certificate = FindUniqueCertificate(filter);
        return certificate is not null;
    }

    /// <summary>
    /// Opens the one X.509 certificate whose <c>CKA_ID</c> is <paramref name="id"/>, or reports that there
    /// is none. Matches exactly as <see cref="OpenCertificate(ReadOnlySpan{byte})"/> does; see
    /// <see cref="TryOpenCertificate(string, out Pkcs11Certificate?)"/> for what returns <see langword="false"/>.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <param name="certificate">The certificate, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one certificate matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenCertificate(ReadOnlySpan<byte> id, [NotNullWhen(true)] out Pkcs11Certificate? certificate)
    {
        if (id.IsEmpty) throw new ArgumentException(EmptyIdMessage, nameof(id));
        using var filter = ObjectTemplate.Empty().Id(id).Build();
        certificate = FindUniqueCertificate(filter);
        return certificate is not null;
    }

    /// <summary>
    /// Opens the one X.509 certificate that matches <paramref name="filter"/>, or reports that there is
    /// none. Matches exactly as <see cref="OpenCertificate(ObjectTemplate)"/> does; see
    /// <see cref="TryOpenCertificate(string, out Pkcs11Certificate?)"/> for what returns <see langword="false"/>.
    /// </summary>
    /// <param name="filter">The attributes to match. Use an <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <param name="certificate">The certificate, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <returns><see langword="true"/> if exactly one certificate matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filter"/> names another class or certificate type.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one certificate matches.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public bool TryOpenCertificate(ObjectTemplate filter, [NotNullWhen(true)] out Pkcs11Certificate? certificate)
    {
        ArgumentNullException.ThrowIfNull(filter);
        certificate = FindUniqueCertificate(filter);
        return certificate is not null;
    }

    /// <summary>
    /// Stores <paramref name="certificate"/> on the token as an X.509 certificate object and returns it.
    /// </summary>
    /// <remarks>
    /// Writes <c>CKA_VALUE</c> (the DER certificate), <c>CKA_SUBJECT</c>, <c>CKA_ISSUER</c> and
    /// <c>CKA_SERIAL_NUMBER</c>, with <paramref name="label"/> and <paramref name="id"/>. The serial number
    /// is optional in PKCS#11 but NSS softoken refuses a certificate without it. Give it the <c>CKA_ID</c> of its key:
    /// that is how <see cref="Pkcs11Certificate.GetPrivateKey"/> and <see cref="Pkcs11Key.GetCertificate"/>
    /// find each other. Only the public certificate is stored, never a private key it may carry.
    /// </remarks>
    /// <param name="certificate">The certificate to store.</param>
    /// <param name="label">The <c>CKA_LABEL</c> to give it.</param>
    /// <param name="id">The <c>CKA_ID</c> to give it, normally its key's. Must not be empty.</param>
    /// <param name="persistOnToken">
    /// <see langword="true"/> to store it on the token (<c>CKA_TOKEN = true</c>); the default creates a
    /// session object, gone when the session closes.
    /// </param>
    /// <returns>The stored certificate. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> or <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_CreateObject</c> call.</exception>
    public Pkcs11Certificate ImportCertificate(X509Certificate2 certificate, string label, ReadOnlySpan<byte> id, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(label);
        if (id.IsEmpty) throw new ArgumentException("Id must not be empty: it links the certificate to its key.", nameof(id));

        using var template = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(label)
            .Id(id)
            .OnToken(persistOnToken)
            .Subject(certificate.SubjectName.RawData)
            .Issuer(certificate.IssuerName.RawData)
            .SerialNumber(EncodedSerialNumber(certificate.RawData))
            .Value(certificate.RawData)
            .Build();
        using var lease = _core.AcquireExclusive(); // see FindKeys
        ObjectHandle handle = _core.CreateObject([.. template.Attributes]);
        return HydrateCertificateFromHandle(handle);
    }

    // CKA_SERIAL_NUMBER is the DER encoding of the serial number (PKCS#11 v3.2 §4.6.3): the INTEGER exactly as
    // the certificate's TBSCertificate holds it, read rather than re-encoded so a certificate whose serial is not
    // minimally encoded keeps the bytes it was issued with.
    private static byte[] EncodedSerialNumber(byte[] certificate)
    {
        var tbs = new AsnReader(certificate, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            tbs.ReadEncodedValue();
        return tbs.ReadEncodedValue().ToArray();
    }

    private Pkcs11Certificate HydrateCertificateFromHandle(ObjectHandle handle)
    {
        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_PRIVATE]);
        if (attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Certificate (CKA_VALUE unreadable)");

        var certificate = X509CertificateLoader.LoadCertificate(attrs[0].GetValueAsByteArray());
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
        bool isPrivate = PrivateObjectLogin.IsPrivate(PrivateObjectLogin.Reported(attrs[3]), CKO.CKO_CERTIFICATE);
        return new Pkcs11Certificate(this, handle, label, id, certificate, isPrivate, CurrentLoginStamp());
    }

    /// <summary>
    /// Opens the private key with the given <c>CKA_ID</c>, or returns <see langword="null"/> when
    /// <paramref name="id"/> is empty or no such key exists. Used by <see cref="Pkcs11Certificate"/>, whose
    /// certificate shares the id: the key-class filter keeps the certificate out of the match.
    /// </summary>
    /// <exception cref="Pkcs11AmbiguousObjectException">More than one private key has this id.</exception>
    internal Pkcs11Key? OpenPrivateKeyById(byte[] id)
    {
        if (id.Length == 0) return null;
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Id(id).Build();
        return FindUniqueKey(filter);
    }

    /// <summary>
    /// Opens the X.509 certificate with the given <c>CKA_ID</c>, or returns <see langword="null"/> when
    /// <paramref name="id"/> is empty or no such certificate exists. Used by <see cref="Pkcs11Key"/>,
    /// whose key objects share the id: the certificate family keeps them out of the match.
    /// </summary>
    /// <exception cref="Pkcs11AmbiguousObjectException">More than one certificate has this id.</exception>
    internal Pkcs11Certificate? OpenCertificateById(byte[] id)
    {
        if (id.Length == 0) return null;
        using var filter = ObjectTemplate.Empty().Id(id).Build();
        return FindUniqueCertificate(filter);
    }

    private Pkcs11Object HydrateObjectFromHandle(ObjectHandle handle)
    {
        // One round trip when the token answers cleanly; the generic two-call read otherwise.
        if (_core.TryReadIdentity(handle, withKeyType: false, out ObjectIdentity identity))
        {
            return new Pkcs11Object(this, handle, identity.ObjectClass, identity.Label, identity.Id,
                identity.IsPrivate, CurrentLoginStamp());
        }

        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_CLASS, CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_PRIVATE]);
        var objectClass = (CKO)attrs[0].GetValueAsUlong();
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
        bool isPrivate = PrivateObjectLogin.IsPrivate(PrivateObjectLogin.Reported(attrs[3]), objectClass);
        return new Pkcs11Object(this, handle, objectClass, label, id, isPrivate, CurrentLoginStamp());
    }

    /// <summary>
    /// Creates a new object on the token from the given template and returns it as a
    /// <see cref="Pkcs11Key"/>. Used for importing pre-existing key material —
    /// <see cref="ObjectTemplate.ForSecretKey(CKK)"/> with <c>.Value(...)</c> for
    /// symmetric keys, or analogous templates for public/private RSA/EC keys.
    /// </summary>
    /// <param name="template">A fully-built template. Will not be modified.</param>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the created object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_CreateObject</c> call.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the template sets <c>CKA_SENSITIVE=false</c> and the session's <see cref="Policy"/> refuses it.</exception>
    public Pkcs11Key ImportKey(ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(template);

        using var lease = _core.AcquireExclusive(); // see FindKeys
        var handle = _core.CreateObject([.. template.Attributes]);
        return HydrateKeyFromHandle(handle);
    }

    /// <summary>
    /// Generates a new symmetric key using <c>C_GenerateKey</c> and returns it as a
    /// <see cref="Pkcs11Key"/>. For asymmetric key generation, use the two-template
    /// overload.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is on the library's insecure-mechanism list and the session's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateKey(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        using var lease = _core.AcquireExclusive(); // see FindKeys
        var handle = _core.GenerateKey(mechanism, [.. template.Attributes]);
        return HydrateKeyFromHandle(handle);
    }

    /// <summary>
    /// Generates a new asymmetric key pair using <c>C_GenerateKeyPair</c> and returns
    /// it as a single <see cref="Pkcs11Key"/> carrying both handles.
    /// </summary>
    /// <remarks>
    /// The templates come in the order <c>C_GenerateKeyPair</c> takes them: public, then private.
    /// Both are <see cref="ObjectTemplate"/>, so swapping them would compile — and the secure
    /// defaults meant for the private key would land on the public one. A template whose
    /// <c>CKA_CLASS</c> names the other half (as the <c>ForPublicKey</c>/<c>ForPrivateKey</c>
    /// builders always set it) is therefore refused.
    /// </remarks>
    /// <param name="mechanism">Key-pair generation mechanism (e.g. <see cref="CKM.CKM_RSA_PKCS_KEY_PAIR_GEN"/>).</param>
    /// <param name="publicKeyTemplate">Template for the public key half.</param>
    /// <param name="privateKeyTemplate">Template for the private key half.</param>
    /// <returns>The new key pair, carrying both handles.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/>, <paramref name="publicKeyTemplate"/>, or <paramref name="privateKeyTemplate"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="publicKeyTemplate"/> sets a <c>CKA_CLASS</c> other than <see cref="CKO.CKO_PUBLIC_KEY"/>, or <paramref name="privateKeyTemplate"/> one other than <see cref="CKO.CKO_PRIVATE_KEY"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure, or the requested key strength is below the secure-defaults baseline, and the session's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateKeyPair(
        Mechanism mechanism,
        ObjectTemplate publicKeyTemplate,
        ObjectTemplate privateKeyTemplate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(publicKeyTemplate);
        ArgumentNullException.ThrowIfNull(privateKeyTemplate);
        RequireClassIfSet(publicKeyTemplate, CKO.CKO_PUBLIC_KEY, nameof(publicKeyTemplate));
        RequireClassIfSet(privateKeyTemplate, CKO.CKO_PRIVATE_KEY, nameof(privateKeyTemplate));

        using var lease = _core.AcquireExclusive(); // see FindKeys
        _core.GenerateKeyPair(
            mechanism,
            [.. publicKeyTemplate.Attributes],
            [.. privateKeyTemplate.Attributes],
            out var publicHandle,
            out var privateHandle);

        // Read identifying metadata off the private side — we already have both
        // handles in hand so we bypass the companion-discovery lookup.
        using var attrs = _core.GetAttributeValue(privateHandle,
        [
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
            CKA.CKA_PRIVATE,
        ]);
        var keyType = (CKK)attrs[0].GetValueAsUlong();
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();

        // The public half's CKA_PRIVATE takes one read of its own: a token may make it private too.
        bool privateHalfIsPrivate = PrivateObjectLogin.IsPrivate(PrivateObjectLogin.Reported(attrs[3]), CKO.CKO_PRIVATE_KEY);
        bool publicHalfIsPrivate = PrivateObjectLogin.IsPrivate(_core.TryReadPrivate(publicHandle), CKO.CKO_PUBLIC_KEY);

        return new Pkcs11Key(
            session: this,
            privateHandle: privateHandle,
            publicHandle: publicHandle,
            keyType: keyType,
            label: label,
            id: id,
            privateHalfIsPrivate: privateHalfIsPrivate,
            publicHalfIsPrivate: publicHalfIsPrivate,
            loginStamp: CurrentLoginStamp());
    }

    private static void RequireClassIfSet(ObjectTemplate template, CKO expected, string paramName)
    {
        ObjectAttribute? contradicting = template.Attributes.FirstOrDefault(attribute =>
            attribute.Type == CKA.CKA_CLASS
            && !attribute.CannotBeRead
            && attribute.GetValueAsUlong() != (ulong)expected);
        if (contradicting is null) return;

        ulong actual = contradicting.GetValueAsUlong();
        throw new ArgumentException(
            $"The template sets CKA_CLASS to {(Enum.IsDefined((CKO)actual) ? ((CKO)actual).ToString() : $"0x{actual:X}")}, " +
            $"but this position takes the {expected} template. The key-pair templates are public first, then private.",
            paramName);
    }

    /// <summary>
    /// Performs ECDH1 key agreement using <paramref name="ecPrivateKey"/> and the peer's public
    /// point, deriving an AES secret key on the token. The derived key is session-only, sensitive,
    /// non-extractable, and non-modifiable — suitable for use with AES-GCM.
    /// </summary>
    /// <remarks>
    /// <b>The peer's point is not validated here.</b> A raw DER-encoded octet string carries no
    /// curve identity, so this overload cannot check that <paramref name="peerPublicPoint"/> is on
    /// the same curve as <paramref name="ecPrivateKey"/> or that it satisfies that curve's equation
    /// — PKCS#11 does not require the token to check either, and skipping both is the invalid-curve
    /// / small-subgroup attack (it recovers a token-resident private key one residue at a time).
    /// The caller is responsible for that validation before calling this overload. Prefer
    /// <see cref="DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/>, which validates the
    /// peer automatically because <see cref="ECParameters"/> carries its own curve.
    /// </remarks>
    /// <param name="ecPrivateKey">The caller's EC private key (must have <c>CKA_DERIVE=true</c>).</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value). Caller-validated — see remarks.</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="kdf">KDF applied to the raw ECDH shared secret before it becomes the derived AES
    /// key's material. Default <see cref="CKD.CKD_SHA256_KDF"/>. <see cref="CKD.CKD_NULL"/> applies no
    /// KDF at all — the token's own truncation/expansion of the raw x-coordinate becomes the AES key
    /// material directly, which NIST SP 800-56A forbids; this method never returns the raw secret for
    /// an off-token KDF step, since the result is always an on-token, non-extractable key. Requires
    /// a policy that permits it (see <see cref="Policy"/>). Some tokens (e.g. SoftHSM 2.x) implement only <c>CKD_NULL</c>.</param>
    /// <returns>The derived AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="ecPrivateKey"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="aesBitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="kdf"/> is not on the session's <see cref="Policy"/> KDF allow-list (under the default policy this includes <see cref="CKD.CKD_NULL"/> and the SHA-1 / SHA-224 KDFs).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The two overloads differ in the required peer-key parameter's type (encoded point vs. ECParameters), so no call site is ambiguous.")]
    public Pkcs11Key DeriveSharedSecretEcdh(
        Pkcs11Key ecPrivateKey,
        ReadOnlySpan<byte> peerPublicPoint,
        int aesBitLength = 256,
        CKD kdf = CKD.CKD_SHA256_KDF)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ecPrivateKey);
        if (aesBitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), "AES key length must be 128, 192, or 256 bits.");
        // The KDF allow-list is enforced by the session on the Derive below, as on every ECDH derivation.
        var p = new CkmEcdh1DeriveParams(kdf, peerPublicPoint);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(aesBitLength / 8)
            .Sensitive().NonExtractable()
            .Encrypt().Decrypt()
            .OnToken(false)
            .Attribute(CKA.CKA_MODIFIABLE, false)
            .Build();
        return ecPrivateKey.Derive(mechanism, template);
    }

    /// <summary>
    /// Performs ECDH1 key agreement using <paramref name="ecPrivateKey"/> and the peer's public key,
    /// deriving an AES secret key on the token. The derived key is session-only, sensitive,
    /// non-extractable, and non-modifiable — suitable for use with AES-GCM.
    /// </summary>
    /// <remarks>
    /// Validates <paramref name="peerPublicKey"/> before it reaches the token: it must be on the
    /// same curve as <paramref name="ecPrivateKey"/>, its coordinates must match that curve's field
    /// size, and the point must satisfy the curve equation — the validation the raw-span overload
    /// cannot perform, because a DER-encoded octet string carries no curve identity for it to check
    /// against. See <see cref="DeriveSharedSecretEcdh(Pkcs11Key, ReadOnlySpan{byte}, int, CKD)"/> for
    /// why that matters (invalid-curve / small-subgroup recovery of the token-resident private key).
    /// </remarks>
    /// <param name="ecPrivateKey">The caller's EC private key (must have <c>CKA_DERIVE=true</c>).</param>
    /// <param name="peerPublicKey">The peer's public key. <see cref="ECParameters.Curve"/> and both coordinates of <see cref="ECParameters.Q"/> are required.</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="kdf">KDF applied to the raw ECDH shared secret before it becomes the derived AES
    /// key's material. Default <see cref="CKD.CKD_SHA256_KDF"/>. <see cref="CKD.CKD_NULL"/> applies no
    /// KDF at all — the token's own truncation/expansion of the raw x-coordinate becomes the AES key
    /// material directly, which NIST SP 800-56A forbids; this method never returns the raw secret for
    /// an off-token KDF step, since the result is always an on-token, non-extractable key. Requires
    /// a policy that permits it (see <see cref="Policy"/>). Some tokens (e.g. SoftHSM 2.x) implement only <c>CKD_NULL</c>.</param>
    /// <returns>The derived AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="ecPrivateKey"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="aesBitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="kdf"/> is not on the session's <see cref="Policy"/> KDF allow-list (under the default policy this includes <see cref="CKD.CKD_NULL"/> and the SHA-1 / SHA-224 KDFs).</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="peerPublicKey"/>'s curve does not match <paramref name="ecPrivateKey"/>'s, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call, or thrown if <paramref name="ecPrivateKey"/>'s <c>CKA_EC_PARAMS</c> cannot be read.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The two overloads differ in the required peer-key parameter's type (encoded point vs. ECParameters), so no call site is ambiguous.")]
    public Pkcs11Key DeriveSharedSecretEcdh(
        Pkcs11Key ecPrivateKey,
        ECParameters peerPublicKey,
        int aesBitLength = 256,
        CKD kdf = CKD.CKD_SHA256_KDF)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ecPrivateKey);

        ValidatedEcdhPeer peer = EcdhPeerValidator.Validate(
            ecPrivateKey, peerPublicKey, nameof(peerPublicKey), "Pkcs11Session.DeriveSharedSecretEcdh");
        return DeriveSharedSecretEcdh(ecPrivateKey, peer.EncodedPoint, aesBitLength, kdf);
    }

    /// <summary>
    /// Reads <paramref name="length"/> bytes from the token's RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate. Must be &gt; 0.</param>
    /// <returns>A newly allocated byte array of length <paramref name="length"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateRandom</c> call.</exception>
    public byte[] GenerateRandom(int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        return _core.GenerateRandom(length);
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with bytes from the token's RNG — the token-backed
    /// counterpart of <see cref="RandomNumberGenerator.Fill(Span{byte})"/>.
    /// </summary>
    /// <remarks>
    /// The token writes straight into <paramref name="destination"/>, so random bytes meant as key
    /// material, IVs or nonces can land in a buffer the caller controls — stack memory, or a pinned
    /// array it zeroes afterwards — with no second copy on the managed heap. An empty span is a no-op,
    /// as with <see cref="RandomNumberGenerator.Fill(Span{byte})"/>.
    /// </remarks>
    /// <param name="destination">The buffer to fill.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateRandom</c> call.</exception>
    public void GenerateRandom(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _core.GenerateRandom(destination);
    }

    /// <summary>
    /// Seeds the token's RNG with the supplied bytes. Optional — many tokens ignore seed
    /// data because they use hardware entropy.
    /// </summary>
    /// <param name="seed">Seed bytes. Must not be empty.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="seed"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_SeedRandom</c> call.</exception>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (seed.IsEmpty)
            throw new ArgumentException("Seed must not be empty.", nameof(seed));
        _core.SeedRandom(seed);
    }

    /// <summary>
    /// Changes a PIN via <c>C_SetPIN</c>: the PIN of the user this application is logged in to the token as, or the
    /// normal user's PIN when it is not logged in (PKCS#11 v3.2). Needs a read/write session. To set the normal
    /// user's PIN as the Security Officer, use <see cref="Pkcs11Login.InitUserPinWithPin"/>.
    /// </summary>
    /// <param name="oldPin">The current PIN.</param>
    /// <param name="newPin">The replacement PIN.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="oldPin"/> or <paramref name="newPin"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11SessionException">A read-only session (<c>CKR_SESSION_READ_ONLY</c>, refused before the module).</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change (e.g. wrong old PIN, policy violation).</exception>
    public void SetPinWithPin(SecurePin oldPin, SecurePin newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        ThrowIfReadOnlyForSetPin();
        _core.SetPin(oldPin, newPin);
    }

    /// <summary>
    /// Changes a PIN, as <see cref="SetPinWithPin"/> does, via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Both the old and new PIN are entered on
    /// the device; PKCS#11 signals this by calling <c>C_SetPIN</c> with both PIN pointers
    /// <c>NULL_PTR</c>. Needs a read/write session.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11SessionException">A read-only session (<c>CKR_SESSION_READ_ONLY</c>, refused before the module).</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change.</exception>
    public void SetPinWithPinpad()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfReadOnlyForSetPin();
        _core.SetPin();
    }

    // PKCS#11 v3.2 C_SetPIN: only in the "R/W Public", "R/W SO Functions" or "R/W User Functions" states, else
    // CKR_SESSION_READ_ONLY. The library opened this session and knows its access, so it answers for the module.
    private void ThrowIfReadOnlyForSetPin()
    {
        if (Access != SessionAccess.ReadOnly)
            return;
        throw Pkcs11Exception.Create(CKR.CKR_SESSION_READ_ONLY, Pkcs11Operations.OpSetPIN,
            $"{Pkcs11Operations.OpSetPIN}: this is a read-only session, and PKCS#11 changes a PIN only in a read/write " +
            "one. Open a read/write session to change it.");
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is a broken digest (e.g. <see cref="CKM.CKM_MD5"/> or <see cref="CKM.CKM_SHA_1"/>) and the session's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Digest</c> call.</exception>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        return _core.Digest(mechanism, data);
    }

    /// <summary>
    /// Hydrates an existing object handle into a Pkcs11Key (used after operations that
    /// produce a new on-token object — Unwrap, Derive). Call it under the lease the operation ran in, so the key
    /// is tied to the login state the object was made under.
    /// </summary>
    internal Pkcs11Key HydrateExistingHandleAsKey(ObjectHandle handle)
        => HydrateKeyFromHandle(handle);

    /// <summary>
    /// Finds the other half of a key pair: the object of <paramref name="companionClass"/> with the same
    /// <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c>. Matching the key type too keeps a short, reused id (a
    /// <c>pkcs11-tool --id 01</c> on several keys) from pairing a key with a public key of another type.
    /// </summary>
    internal ObjectHandle FindCompanion(CKO companionClass, byte[] id, CKK keyType)
    {
        using var lease = _core.AcquireExclusive();
        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)companionClass)
            .Attribute(CKA.CKA_KEY_TYPE, (ulong)keyType)
            .Id(id)
            .Build();
        var handles = _core.FindAllObjects([.. filter.Attributes]);
        return handles.Count > 0 ? handles[0] : ObjectHandle.Invalid;
    }

    /// <summary>
    /// Whether a key half the library found without reading its identity (a key's other half) is a private object:
    /// one <c>CKA_PRIVATE</c> read, or by class when the token does not report it.
    /// </summary>
    internal bool IsPrivateObject(ObjectHandle handle, CKO objectClass)
        => PrivateObjectLogin.IsPrivate(_core.TryReadPrivate(handle), objectClass);

    /// <summary>
    /// The token's login state now, for a private object found or made under it. Call it under the lease the
    /// lookup or creation ran in.
    /// </summary>
    internal LoginStamp CurrentLoginStamp() => _core.LoginRecord.CurrentStamp();

    // The lookups by CKA_ID refuse an empty id: it matches every object that has no CKA_ID.
    private const string EmptyIdMessage = "Id must not be empty.";

    /// <summary>
    /// A family of objects a lookup returns as one wrapper type: the classes it spans, and an attribute
    /// every member has (certificates: <c>CKA_CERTIFICATE_TYPE = CKC_X_509</c>, since
    /// <see cref="Pkcs11Certificate"/> holds an <see cref="X509Certificate2"/>).
    /// </summary>
    private sealed record ObjectFamily(string Name, CKO[] Classes, CKA? FixedAttribute = null, ulong FixedValue = 0);

    private static readonly ObjectFamily Keys =
        new("key", [CKO.CKO_PRIVATE_KEY, CKO.CKO_PUBLIC_KEY, CKO.CKO_SECRET_KEY]);

    private static readonly ObjectFamily Certificates =
        new("certificate", [CKO.CKO_CERTIFICATE], CKA.CKA_CERTIFICATE_TYPE, (ulong)CKC.CKC_X_509);

    private static bool IsKeyClass(CKO objectClass) => Array.IndexOf(Keys.Classes, objectClass) >= 0;

    private Pkcs11Key OpenKeyCore(ObjectTemplate filter, string criteria)
        => FindUniqueKey(filter)
            ?? throw new Pkcs11ObjectNotFoundException(Pkcs11Operations.OpFindObjects, $"No key {criteria} was found on the token.");

    private Pkcs11Key? FindUniqueKey(ObjectTemplate filter)
        => FindUnique(filter, Keys, GroupKeyHalves, HydrateKeyGroup);

    private Pkcs11Object? FindUniqueObject(ObjectTemplate filter, ObjectFamily family)
        => FindUnique(filter, family, EachOnItsOwn, matched => HydrateObjectFromHandle(matched[0].Handle));

    /// <summary>
    /// The family of the class <paramref name="filter"/> names, for the generic object lookups: any class
    /// but the key and certificate ones, which have typed lookups of their own.
    /// </summary>
    private static ObjectFamily OtherObjects(ObjectTemplate filter)
    {
        ObjectAttribute named = filter.Attributes.FirstOrDefault(a => a.Type == CKA.CKA_CLASS)
            ?? throw new ArgumentException("The filter must name a CKA_CLASS, e.g. ObjectTemplate.ForData().", nameof(filter));

        var objectClass = (CKO)named.GetValueAsUlong();
        if (Array.IndexOf(Keys.Classes, objectClass) >= 0)
            throw new ArgumentException($"{objectClass} is a key class: open keys with OpenKey.", nameof(filter));
        if (Array.IndexOf(Certificates.Classes, objectClass) >= 0)
            throw new ArgumentException($"{objectClass} is the certificate class: open certificates with OpenCertificate.", nameof(filter));
        return new ObjectFamily($"{objectClass} object", [objectClass]);
    }

    private Pkcs11Certificate OpenCertificateCore(ObjectTemplate filter, string criteria)
        => FindUniqueCertificate(filter)
            ?? throw new Pkcs11ObjectNotFoundException(Pkcs11Operations.OpFindObjects, $"No certificate {criteria} was found on the token.");

    private Pkcs11Certificate? FindUniqueCertificate(ObjectTemplate filter)
        => FindUnique(filter, Certificates, EachOnItsOwn, matched => HydrateCertificateFromHandle(matched[0].Handle));

    /// <summary>An object a lookup matched, with the attributes that decide which result it belongs to.</summary>
    private sealed record ObjectCandidate(ObjectHandle Handle, CKO Class, CKK? KeyType, byte[] Id, string? Label, bool? Private);

    /// <summary>
    /// Runs a lookup that must identify one object of <paramref name="family"/>: searches with
    /// <see cref="SearchFamily"/>, groups the matches into results with <paramref name="group"/> and
    /// builds the one result with <paramref name="hydrate"/>, or returns <see langword="null"/> when
    /// nothing matched.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="filter"/> contradicts the family.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">The matches form more than one result.</exception>
    private T? FindUnique<T>(
        ObjectTemplate filter, ObjectFamily family,
        Func<List<ObjectCandidate>, List<List<ObjectCandidate>>> group, Func<List<ObjectCandidate>, T> hydrate)
        where T : class
    {
        using var lease = _core.AcquireExclusive(); // see FindKeys
        List<ObjectCandidate> candidates =
            [.. SearchFamily(filter, family).Select(match => ReadCandidate(match.Handle, match.Class))];

        List<List<ObjectCandidate>> results = group(candidates);
        return results.Count switch
        {
            0 => null,
            1 => hydrate(results[0]),
            _ => throw new Pkcs11AmbiguousObjectException(Pkcs11Operations.OpFindObjects,
                $"The lookup matched {results.Count} distinct {family.Name}s; refusing to pick one. Narrow it with a " +
                "filter (class, type, CKA_ID, …), or enumerate the candidates with a Find method."),
        };
    }

    // Single-member groups, for the families that have no pairs.
    private static List<List<ObjectCandidate>> EachOnItsOwn(List<ObjectCandidate> candidates)
        => [.. candidates.Select(c => new List<ObjectCandidate> { c })];

    /// <summary>
    /// Every object of <paramref name="family"/> that matches <paramref name="filter"/>, with its class.
    /// </summary>
    /// <remarks>
    /// PKCS#11 has no "class is one of" filter, so a search across a family is one search per class,
    /// which is also what keeps objects of other families out. A <c>CKA_CLASS</c> in
    /// <paramref name="filter"/> narrows the search to that class and must belong to the family; the
    /// family's fixed attribute is added unless the filter already names it, with the same value.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="filter"/> names a class outside the family, or another value for its fixed attribute.</exception>
    private List<(ObjectHandle Handle, CKO Class)> SearchFamily(ObjectTemplate filter, ObjectFamily family)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        CKO[] classes = ClassesToSearch(filter, family);
        List<ObjectAttribute> criteria = [.. filter.Attributes.Where(a => a.Type != CKA.CKA_CLASS)];

        using ObjectAttribute? fixedAttribute = family.FixedAttribute is { } type ? new ObjectAttribute(type, family.FixedValue) : null;
        if (fixedAttribute is not null)
        {
            ObjectAttribute? given = criteria.Find(a => a.Type == fixedAttribute.Type);
            if (given is null)
                criteria.Add(fixedAttribute);
            else if (given.GetValueAsUlong() != family.FixedValue)
                throw new ArgumentException(
                    $"A {family.Name} has {fixedAttribute.Type} = 0x{family.FixedValue:X}; the filter asks for 0x{given.GetValueAsUlong():X}.", nameof(filter));
        }

        List<(ObjectHandle, CKO)> matches = [];
        foreach (CKO objectClass in classes)
        {
            using var classAttribute = new ObjectAttribute(CKA.CKA_CLASS, objectClass);
            foreach (ObjectHandle handle in _core.FindAllObjects([.. criteria, classAttribute]))
                matches.Add((handle, objectClass));
        }
        return matches;
    }

    // The family's classes, or the class the filter names, which must be among them. A template holds
    // each attribute once (its builder replaces a repeated one), so there is at most one CKA_CLASS.
    private static CKO[] ClassesToSearch(ObjectTemplate filter, ObjectFamily family)
    {
        ObjectAttribute? named = filter.Attributes.FirstOrDefault(a => a.Type == CKA.CKA_CLASS);
        if (named is null)
            return family.Classes;

        var objectClass = (CKO)named.GetValueAsUlong();
        return Array.IndexOf(family.Classes, objectClass) >= 0
            ? [objectClass]
            : throw new ArgumentException($"The filter's CKA_CLASS {objectClass} is not a {family.Name} class.", nameof(filter));
    }

    private ObjectCandidate ReadCandidate(ObjectHandle handle, CKO objectClass)
    {
        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_PRIVATE]);
        CKK? keyType = attrs[0].CannotBeRead ? null : (CKK)attrs[0].GetValueAsUlong();
        byte[] id = attrs[1].CannotBeRead ? [] : attrs[1].GetValueAsByteArray();
        string? label = attrs[2].CannotBeRead ? null : attrs[2].GetValueAsString();
        return new ObjectCandidate(handle, objectClass, keyType, id, label, PrivateObjectLogin.Reported(attrs[3]));
    }

    /// <summary>
    /// Groups key matches into keys: a private and a public key with the same <c>CKA_ID</c> and
    /// <c>CKA_KEY_TYPE</c> are the two halves of one key — an empty id included, since a pair generated
    /// without an id still shares the label the lookup matched. Every other match — each secret key, and
    /// a second private or public key with the same id and type — is a key of its own. Halves whose key
    /// type the token does not report are not paired: nothing shows they belong together.
    /// </summary>
    private static List<List<ObjectCandidate>> GroupKeyHalves(List<ObjectCandidate> candidates)
    {
        List<List<ObjectCandidate>> keys = [];
        foreach (ObjectCandidate candidate in candidates)
        {
            // A half joins an existing key only as that key's missing other half.
            List<ObjectCandidate>? pair = candidate.Class == CKO.CKO_SECRET_KEY
                ? null
                : keys.Find(k => k.Count == 1
                    && k[0].Class != CKO.CKO_SECRET_KEY
                    && k[0].Class != candidate.Class
                    && k[0].KeyType is not null
                    && k[0].KeyType == candidate.KeyType
                    && k[0].Id.AsSpan().SequenceEqual(candidate.Id));

            if (pair is null)
                keys.Add([candidate]);
            else
                pair.Add(candidate);
        }
        return keys;
    }

    private Pkcs11Key HydrateKeyGroup(List<ObjectCandidate> key)
    {
        // One half matched: the other is found by CKA_ID on first use, as for any opened key.
        if (key.Count == 1)
            return HydrateKeyFromHandle(key[0].Handle);

        ObjectCandidate privateHalf = key.Find(c => c.Class == CKO.CKO_PRIVATE_KEY)!;
        ObjectCandidate publicHalf = key.Find(c => c.Class == CKO.CKO_PUBLIC_KEY)!;
        return new Pkcs11Key(
            session: this,
            privateHandle: privateHalf.Handle,
            publicHandle: publicHalf.Handle,
            keyType: privateHalf.KeyType!.Value,
            label: privateHalf.Label ?? publicHalf.Label,
            id: privateHalf.Id,
            privateHalfIsPrivate: PrivateObjectLogin.IsPrivate(privateHalf.Private, CKO.CKO_PRIVATE_KEY),
            publicHalfIsPrivate: PrivateObjectLogin.IsPrivate(publicHalf.Private, CKO.CKO_PUBLIC_KEY),
            loginStamp: CurrentLoginStamp());
    }

    /// <summary>
    /// Reads CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_PRIVATE off the handle and constructs a
    /// <see cref="Pkcs11Key"/>. A private or public key with a non-empty CKA_ID is marked to look up
    /// its other half the first time an operation needs it; nothing is searched here.
    /// </summary>
    private Pkcs11Key HydrateKeyFromHandle(ObjectHandle handle)
        => HydrateKeyFromHandle(handle, keysOnly: false)!;

    /// <summary>
    /// Wraps a found object as a key, reading its class, key type, label and id in one call when the token
    /// answers cleanly. With <paramref name="keysOnly"/>, an object whose class is not a key class
    /// (a certificate that shares its key's <c>CKA_ID</c>, say) returns <see langword="null"/> instead of
    /// failing on the <c>CKA_KEY_TYPE</c> it does not have.
    /// </summary>
    private Pkcs11Key? HydrateKeyFromHandle(ObjectHandle handle, bool keysOnly)
    {
        CKO objectClass;
        CKK keyType;
        string? label;
        byte[] id;
        bool isPrivate;

        // One round trip when the token answers cleanly; the generic two-call read otherwise.
        if (_core.TryReadIdentity(handle, withKeyType: true, out ObjectIdentity identity))
        {
            (objectClass, keyType, label, id, isPrivate) = identity;
            if (keysOnly && !IsKeyClass(objectClass))
                return null;
        }
        else
        {
            using var attrs = _core.GetAttributeValue(handle,
            [
                CKA.CKA_CLASS,
                CKA.CKA_KEY_TYPE,
                CKA.CKA_LABEL,
                CKA.CKA_ID,
                CKA.CKA_PRIVATE,
            ]);
            objectClass = (CKO)attrs[0].GetValueAsUlong();
            if (keysOnly && !IsKeyClass(objectClass))
                return null;
            keyType = (CKK)attrs[1].GetValueAsUlong();
            label = attrs[2].CannotBeRead ? null : attrs[2].GetValueAsString();
            id = attrs[3].CannotBeRead ? [] : attrs[3].GetValueAsByteArray();
            isPrivate = PrivateObjectLogin.IsPrivate(PrivateObjectLogin.Reported(attrs[4]), objectClass);
        }

        ObjectHandle privateHandle = ObjectHandle.Invalid;
        ObjectHandle publicHandle = ObjectHandle.Invalid;

        // A private key is paired with its public key, and a public key with its private key (a
        // search may return either half first, and Sign/Decrypt need the private one). The search
        // waits for first use: a listing of N keys would otherwise scan the token N more times for
        // halves the caller may never touch. Without an id there is no reliable way to match.
        bool companionPending = false;
        if (objectClass == CKO.CKO_PRIVATE_KEY)
        {
            privateHandle = handle;
            companionPending = id.Length > 0;
        }
        else if (objectClass == CKO.CKO_PUBLIC_KEY)
        {
            publicHandle = handle;
            companionPending = id.Length > 0;
        }
        else // CKO_SECRET_KEY or other
        {
            privateHandle = handle;
        }

        return new Pkcs11Key(
            session: this,
            privateHandle: privateHandle,
            publicHandle: publicHandle,
            keyType: keyType,
            label: label,
            id: id,
            companionPending: companionPending,
            privateHalfIsPrivate: isPrivate && objectClass != CKO.CKO_PUBLIC_KEY,
            publicHalfIsPrivate: isPrivate && objectClass == CKO.CKO_PUBLIC_KEY,
            loginStamp: CurrentLoginStamp());
    }
}
