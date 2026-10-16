using System.Diagnostics.CodeAnalysis;
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
/// Construction is exclusively via <see cref="Pkcs11Library.OpenSessionWithPin(string, CKU, SecurePin, ICryptoPolicy?)"/>,
/// <see cref="Pkcs11Library.OpenSessionWithPinpad(string, CKU, ICryptoPolicy?)"/>, or
/// <see cref="Pkcs11Library.OpenSessionWithoutLogin(string, ICryptoPolicy?)"/>, which open the
/// session (<c>C_OpenSession</c>) and, for the first two, log in (<c>C_Login</c>).
/// The session does not own the library — callers continue to own and dispose the
/// <see cref="Pkcs11Library"/>. On <see cref="Dispose"/> it logs the user out (<c>C_Logout</c>,
/// best-effort — a token-wide state change, since PKCS#11 login state is per-application/slot) and
/// then closes the session (<c>C_CloseSession</c>), so the HSM audit log records an explicit logout,
/// not just a session close. A logout that fails because no user was logged in is ignored.
/// </para>
/// <para>
/// Keys obtained via the session's factory methods hold a non-owning reference to the
/// session. The session must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Session : IDisposable
{
    private readonly Pkcs11SessionCore _core;
    private bool _disposed;

    internal Pkcs11Session(Pkcs11Library library, Pkcs11Slot slot, Pkcs11SessionCore core)
    {
        Library = library;
        Slot = slot;
        _core = core;
    }

    /// <summary>The slot this session is authenticated against.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>The library that hosts this session. The session does not own the library.</summary>
    public Pkcs11Library Library { get; }

    /// <summary>The session's native calls and policy enforcement. Used by <c>Pkcs11Key</c> to delegate operations.</summary>
    internal Pkcs11SessionCore Core => _core;

    /// <summary>Submits <paramref name="request"/> to the session's effective policy; throws on denial.</summary>
    internal void Enforce(PolicyRequest request) => _core.Enforce(request);

    /// <summary>Evaluates <paramref name="request"/> without throwing or logging.</summary>
    internal bool IsPermitted(PolicyRequest request) => _core.IsPermitted(request);

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
    /// <see cref="ICryptoPolicy.AllowsOverride"/> is false (for example <c>CryptoPolicy.FipsOnly</c>).</exception>
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

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;

        // Explicitly log out before closing the session so the token's audit log records a
        // logout, not just a session close. Best-effort: the caller may have already logged out
        // (CKR_USER_NOT_LOGGED_IN), or the library/session may already be torn down — none of
        // those should make disposal throw. C_Logout affects the whole application's login state
        // on the slot, which is the intended end-of-context behaviour for an owned session.
        // LogoutForDispose waits out a call in flight on another thread instead of throwing on
        // the contention: the session close below must always be reached.
        try
        {
            _core.LogoutForDispose();
        }
        catch (Exception ex) when (ex is Pkcs11Exception or ObjectDisposedException)
        {
            // Already logged out, session/library already gone (disposing the library closes every
            // session it tracks, so the logout finds this one closed), or token rejected the logout
            // during teardown — disposal proceeds regardless.
        }

        _core.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_LABEL</c> is <paramref name="label"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only key objects match — certificates and data objects that share the label are ignored — and
    /// <paramref name="keyClass"/> narrows the search to one key class. The lookup must identify
    /// exactly one key; anything more is refused with <see cref="Pkcs11AmbiguousObjectException"/>
    /// rather than resolved by picking a match, which would let whoever can create objects on the
    /// token decide which key an operation uses.
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
    /// <param name="keyClass">
    /// <see cref="CKO.CKO_PRIVATE_KEY"/>, <see cref="CKO.CKO_PUBLIC_KEY"/> or
    /// <see cref="CKO.CKO_SECRET_KEY"/> to match only that class; <see langword="null"/> for any key.
    /// </param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyClass"/> is not a key class.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if no key matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one key matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    [SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The overloads differ in the required lookup parameter's type (label vs. CKA_ID bytes), so no call site is ambiguous.")]
    public Pkcs11Key OpenKey(string label, CKO? keyClass = null)
        => TryOpenKey(label, out Pkcs11Key? key, keyClass)
            ? key
            : throw new KeyNotFoundException($"No {DescribeKeyClass(keyClass)} with label '{label}' was found on the token.");

    /// <summary>
    /// Opens the one key whose <c>CKA_ID</c> is <paramref name="id"/>. See
    /// <see cref="OpenKey(string, CKO?)"/> for which objects match and when the lookup is ambiguous.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <param name="keyClass">
    /// <see cref="CKO.CKO_PRIVATE_KEY"/>, <see cref="CKO.CKO_PUBLIC_KEY"/> or
    /// <see cref="CKO.CKO_SECRET_KEY"/> to match only that class; <see langword="null"/> for any key.
    /// </param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyClass"/> is not a key class.</exception>
    /// <exception cref="KeyNotFoundException">Thrown if no key matches.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one key matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    [SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The overloads differ in the required lookup parameter's type (label vs. CKA_ID bytes), so no call site is ambiguous.")]
    public Pkcs11Key OpenKey(ReadOnlySpan<byte> id, CKO? keyClass = null)
        => TryOpenKey(id, out Pkcs11Key? key, keyClass)
            ? key
            : throw new KeyNotFoundException($"No {DescribeKeyClass(keyClass)} with the given id ({id.Length} bytes) was found on the token.");

    /// <summary>
    /// Opens the one key whose <c>CKA_LABEL</c> is <paramref name="label"/>, or reports that there is
    /// none. Matches exactly as <see cref="OpenKey(string, CKO?)"/> does.
    /// </summary>
    /// <remarks>
    /// Only "no match" returns <see langword="false"/>. Several matches still throw
    /// <see cref="Pkcs11AmbiguousObjectException"/>: that is a problem with the token's contents, not
    /// an absent key.
    /// </remarks>
    /// <param name="label">The <c>CKA_LABEL</c> to match.</param>
    /// <param name="key">The key, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <param name="keyClass">
    /// <see cref="CKO.CKO_PRIVATE_KEY"/>, <see cref="CKO.CKO_PUBLIC_KEY"/> or
    /// <see cref="CKO.CKO_SECRET_KEY"/> to match only that class; <see langword="null"/> for any key.
    /// </param>
    /// <returns><see langword="true"/> if exactly one key matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyClass"/> is not a key class.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one key matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    [SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The overloads differ in the required lookup parameter's type (label vs. CKA_ID bytes), so no call site is ambiguous.")]
    public bool TryOpenKey(string label, [NotNullWhen(true)] out Pkcs11Key? key, CKO? keyClass = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(label);

        key = FindUniqueKey(b => b.Label(label), keyClass);
        return key is not null;
    }

    /// <summary>
    /// Opens the one key whose <c>CKA_ID</c> is <paramref name="id"/>, or reports that there is none.
    /// Matches exactly as <see cref="OpenKey(string, CKO?)"/> does; see
    /// <see cref="TryOpenKey(string, out Pkcs11Key?, CKO?)"/> for what returns <see langword="false"/>.
    /// </summary>
    /// <param name="id">The <c>CKA_ID</c> bytes to match. Must not be empty.</param>
    /// <param name="key">The key, when one matched; the caller must <c>Dispose</c> it.</param>
    /// <param name="keyClass">
    /// <see cref="CKO.CKO_PRIVATE_KEY"/>, <see cref="CKO.CKO_PUBLIC_KEY"/> or
    /// <see cref="CKO.CKO_SECRET_KEY"/> to match only that class; <see langword="null"/> for any key.
    /// </param>
    /// <returns><see langword="true"/> if exactly one key matched.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyClass"/> is not a key class.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">Thrown if more than one key matches.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    [SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The overloads differ in the required lookup parameter's type (label vs. CKA_ID bytes), so no call site is ambiguous.")]
    public bool TryOpenKey(ReadOnlySpan<byte> id, [NotNullWhen(true)] out Pkcs11Key? key, CKO? keyClass = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (id.IsEmpty) throw new ArgumentException("Id must not be empty.", nameof(id));

        byte[] idBytes = id.ToArray();
        key = FindUniqueKey(b => b.Id(idBytes), keyClass);
        return key is not null;
    }

    /// <summary>
    /// Finds all keys matching the given template.
    /// </summary>
    /// <remarks>
    /// The other half of a key pair (same <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c>) is looked up the first
    /// time an operation on the key needs it, not here. If that lookup fails, the error comes from that
    /// operation (<c>Verify</c>, <c>Encrypt</c>, <c>Sign</c>, <c>GetAttributeValue</c>, …), and the
    /// next use looks again.
    /// </remarks>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A list of <see cref="Pkcs11Key"/>. May be empty. The list owns the keys: dispose it
    /// (a <see langword="using"/> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Key> FindKeys(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _core.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Key>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateKeyFromHandle(handle));
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

        var handles = _core.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Object>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateObjectFromHandle(handle));
        return new ReadOnlyDisposableList<Pkcs11Object>(result);
    }

    /// <summary>
    /// Finds all certificate objects on the token (<c>CKA_CLASS = CKO_CERTIFICATE</c>) — a typed
    /// counterpart to <see cref="FindKeys"/>. Each <see cref="Pkcs11Certificate"/> exposes the
    /// parsed <see cref="X509Certificate2"/> and bridges to its on-token private key by
    /// <c>CKA_ID</c>.
    /// </summary>
    /// <returns>A list of <see cref="Pkcs11Certificate"/>. May be empty. The list owns the certificates:
    /// dispose it (a <see langword="using"/> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if a certificate's
    /// <c>CKA_VALUE</c> cannot be read; also propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Certificate> FindCertificates()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_CERTIFICATE)
            .Build();

        var handles = _core.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Certificate>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateCertificateFromHandle(handle));
        return new ReadOnlyDisposableList<Pkcs11Certificate>(result);
    }

    private Pkcs11Certificate HydrateCertificateFromHandle(ObjectHandle handle)
    {
        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID]);
        if (attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "FindCertificates (CKA_VALUE unreadable)");

        var certificate = X509CertificateLoader.LoadCertificate(attrs[0].GetValueAsByteArray());
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
        return new Pkcs11Certificate(this, handle, label, id, certificate);
    }

    /// <summary>
    /// Opens the private key with the given <c>CKA_ID</c>, or returns <see langword="null"/> when
    /// <paramref name="id"/> is empty or no such key exists. Used by <see cref="Pkcs11Certificate"/>, whose
    /// certificate shares the id: the key-class filter keeps the certificate out of the match.
    /// </summary>
    /// <exception cref="Pkcs11AmbiguousObjectException">More than one private key has this id.</exception>
    internal Pkcs11Key? OpenPrivateKeyById(byte[] id)
        => id.Length == 0 ? null : FindUniqueKey(b => b.Id(id), CKO.CKO_PRIVATE_KEY);

    private Pkcs11Object HydrateObjectFromHandle(ObjectHandle handle)
    {
        // One round trip when the token answers cleanly; the generic two-call read otherwise.
        if (_core.TryReadIdentity(handle, withKeyType: false, out ObjectIdentity identity))
            return new Pkcs11Object(this, handle, identity.ObjectClass, identity.Label, identity.Id);

        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_CLASS, CKA.CKA_LABEL, CKA.CKA_ID]);
        var objectClass = (CKO)attrs[0].GetValueAsUlong();
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
        return new Pkcs11Object(this, handle, objectClass, label, id);
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
        ]);
        var keyType = (CKK)attrs[0].GetValueAsUlong();
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();

        return new Pkcs11Key(
            session: this,
            privateHandle: privateHandle,
            publicHandle: publicHandle,
            keyType: keyType,
            label: label,
            id: id);
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
    /// Changes the logged-in user's PIN via <c>C_SetPIN</c>. The session must be authenticated as
    /// the user (or SO) whose PIN is being changed.
    /// </summary>
    /// <param name="oldPin">The current PIN.</param>
    /// <param name="newPin">The replacement PIN.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="oldPin"/> or <paramref name="newPin"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change (e.g. wrong old PIN, policy violation).</exception>
    public void SetPinWithPin(SecurePin oldPin, SecurePin newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        _core.SetPin(oldPin, newPin);
    }

    /// <summary>
    /// Changes the logged-in user's PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Both the old and new PIN are entered on
    /// the device; PKCS#11 signals this by calling <c>C_SetPIN</c> with both PIN pointers
    /// <c>NULL_PTR</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change.</exception>
    public void SetPinWithPinpad()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _core.SetPin();
    }

    /// <summary>
    /// Initializes the normal user's PIN via <c>C_InitPIN</c>. Requires a session authenticated as
    /// the Security Officer (SO).
    /// </summary>
    /// <param name="userPin">The user PIN to set.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="userPin"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the operation (e.g. not logged in as SO).</exception>
    public void InitPinWithPin(SecurePin userPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(userPin);
        _core.InitPin(userPin);
    }

    /// <summary>
    /// Initializes the normal user's PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Requires a session authenticated as the
    /// Security Officer (SO); PKCS#11 signals on-device entry by calling <c>C_InitPIN</c> with
    /// <c>pPin = NULL_PTR</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the operation (e.g. not logged in as SO).</exception>
    public void InitPinWithPinpad()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _core.InitPin();
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
    /// produce a new on-token object — Unwrap, Derive).
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
        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)companionClass)
            .Attribute(CKA.CKA_KEY_TYPE, (ulong)keyType)
            .Id(id)
            .Build();
        var handles = _core.FindAllObjects([.. filter.Attributes]);
        return handles.Count > 0 ? handles[0] : ObjectHandle.Invalid;
    }

    private static readonly CKO[] KeyClasses = [CKO.CKO_PRIVATE_KEY, CKO.CKO_PUBLIC_KEY, CKO.CKO_SECRET_KEY];

    private static string DescribeKeyClass(CKO? keyClass) => keyClass switch
    {
        CKO.CKO_PRIVATE_KEY => "private key",
        CKO.CKO_PUBLIC_KEY => "public key",
        CKO.CKO_SECRET_KEY => "secret key",
        _ => "key",
    };

    /// <summary>A key object a lookup matched, with the attributes that decide which key it belongs to.</summary>
    private sealed record KeyCandidate(ObjectHandle Handle, CKO Class, CKK KeyType, byte[] Id, string? Label);

    /// <summary>
    /// Runs a lookup that must identify one key: searches each requested key class with
    /// <paramref name="criteria"/>, groups the matches into distinct keys and returns the one key, or
    /// <see langword="null"/> when nothing matched.
    /// </summary>
    /// <remarks>
    /// A private and a public key with the same <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c> are the two
    /// halves of one key — an empty id included, since a pair generated without an id still shares
    /// the label the lookup matched. Every other match — each secret key, and a second private or
    /// public key with the same id and type — is a key of its own. PKCS#11 has no "class is one
    /// of" filter, so an unrestricted lookup is one search per key class, which is also what keeps
    /// certificates and data objects out of the match.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="keyClass"/> is not a key class.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">The matches form more than one key.</exception>
    private Pkcs11Key? FindUniqueKey(Func<GenericTemplateBuilder, GenericTemplateBuilder> criteria, CKO? keyClass)
    {
        if (keyClass is { } requested && Array.IndexOf(KeyClasses, requested) < 0)
            throw new ArgumentOutOfRangeException(nameof(keyClass), requested,
                "Must be CKO_PRIVATE_KEY, CKO_PUBLIC_KEY or CKO_SECRET_KEY, or null for any key.");

        List<KeyCandidate> candidates = [];
        foreach (CKO objectClass in keyClass is { } only ? [only] : KeyClasses)
        {
            using var filter = criteria(ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)objectClass)).Build();
            foreach (ObjectHandle handle in _core.FindAllObjects([.. filter.Attributes]))
                candidates.Add(ReadCandidate(handle, objectClass));
        }

        List<List<KeyCandidate>> keys = GroupIntoKeys(candidates);
        return keys.Count switch
        {
            0 => null,
            1 => HydrateGroup(keys[0]),
            _ => throw new Pkcs11AmbiguousObjectException("C_FindObjects",
                $"The lookup matched {keys.Count} distinct keys; refusing to pick one. Narrow it by key class " +
                "or CKA_ID, or enumerate the candidates with FindKeys."),
        };
    }

    private KeyCandidate ReadCandidate(ObjectHandle handle, CKO objectClass)
    {
        using var attrs = _core.GetAttributeValue(handle, [CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_LABEL]);
        var keyType = (CKK)attrs[0].GetValueAsUlong();
        byte[] id = attrs[1].CannotBeRead ? [] : attrs[1].GetValueAsByteArray();
        string? label = attrs[2].CannotBeRead ? null : attrs[2].GetValueAsString();
        return new KeyCandidate(handle, objectClass, keyType, id, label);
    }

    private static List<List<KeyCandidate>> GroupIntoKeys(List<KeyCandidate> candidates)
    {
        List<List<KeyCandidate>> keys = [];
        foreach (KeyCandidate candidate in candidates)
        {
            // A half joins an existing key only as that key's missing other half; a second private
            // (or public) key with the same id is a different key.
            List<KeyCandidate>? pair = candidate.Class == CKO.CKO_SECRET_KEY
                ? null
                : keys.Find(k => k.Count == 1
                    && k[0].Class != CKO.CKO_SECRET_KEY
                    && k[0].Class != candidate.Class
                    && k[0].KeyType == candidate.KeyType
                    && k[0].Id.AsSpan().SequenceEqual(candidate.Id));

            if (pair is null)
                keys.Add([candidate]);
            else
                pair.Add(candidate);
        }
        return keys;
    }

    private Pkcs11Key HydrateGroup(List<KeyCandidate> key)
    {
        // One half matched: the other is found by CKA_ID on first use, as for any opened key.
        if (key.Count == 1)
            return HydrateKeyFromHandle(key[0].Handle);

        KeyCandidate privateHalf = key.Find(c => c.Class == CKO.CKO_PRIVATE_KEY)!;
        KeyCandidate publicHalf = key.Find(c => c.Class == CKO.CKO_PUBLIC_KEY)!;
        return new Pkcs11Key(
            session: this,
            privateHandle: privateHalf.Handle,
            publicHandle: publicHalf.Handle,
            keyType: privateHalf.KeyType,
            label: privateHalf.Label ?? publicHalf.Label,
            id: privateHalf.Id);
    }

    /// <summary>
    /// Reads CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID off the handle and constructs a
    /// <see cref="Pkcs11Key"/>. A private or public key with a non-empty CKA_ID is marked to look up
    /// its other half the first time an operation needs it; nothing is searched here.
    /// </summary>
    private Pkcs11Key HydrateKeyFromHandle(ObjectHandle handle)
    {
        CKO objectClass;
        CKK keyType;
        string? label;
        byte[] id;

        // One round trip when the token answers cleanly; the generic two-call read otherwise.
        if (_core.TryReadIdentity(handle, withKeyType: true, out ObjectIdentity identity))
        {
            (objectClass, keyType, label, id) = identity;
        }
        else
        {
            using var attrs = _core.GetAttributeValue(handle,
            [
                CKA.CKA_CLASS,
                CKA.CKA_KEY_TYPE,
                CKA.CKA_LABEL,
                CKA.CKA_ID,
            ]);
            objectClass = (CKO)attrs[0].GetValueAsUlong();
            keyType = (CKK)attrs[1].GetValueAsUlong();
            label = attrs[2].CannotBeRead ? null : attrs[2].GetValueAsString();
            id = attrs[3].CannotBeRead ? [] : attrs[3].GetValueAsByteArray();
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
            companionPending: companionPending);
    }
}
