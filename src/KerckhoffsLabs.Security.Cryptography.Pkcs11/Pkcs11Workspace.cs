using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Authenticated context against a PKCS#11 token. Holds the library, slot, and active
/// session and exposes the operations a caller performs while logged in: key lookup,
/// generation, import, RNG access, and one-shot digests.
/// </summary>
/// <remarks>
/// <para>
/// Construction is exclusively via <see cref="Pkcs11Library.OpenWorkspaceWithPin(string, CKU, SecurePin, ICryptoPolicy?)"/>,
/// <see cref="Pkcs11Library.OpenWorkspaceWithPinpad(string, CKU, ICryptoPolicy?)"/>, or
/// <see cref="Pkcs11Library.OpenWorkspaceWithoutLogin(string, ICryptoPolicy?)"/>.
/// The workspace does not own the library — callers continue to own and dispose the
/// <see cref="Pkcs11Library"/>. The workspace owns the session it opened. On
/// <see cref="Dispose"/> it logs the user out (<c>C_Logout</c>, best-effort — a token-wide
/// state change, since PKCS#11 login state is per-application/slot) and then closes the
/// session (<c>C_CloseSession</c>), so the HSM audit log records an explicit logout, not just
/// a session close. A logout that fails because no user was logged in is ignored.
/// </para>
/// <para>
/// Keys obtained via the workspace's factory methods hold a non-owning reference to the
/// workspace. The workspace must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed class Pkcs11Workspace : IDisposable
{
    private const string AesKeyLengthMessage = "AES key length must be 128, 192, or 256 bits.";

    private readonly Pkcs11Session _session;
    private bool _disposed;

    internal Pkcs11Workspace(Pkcs11Library library, Pkcs11Slot slot, Pkcs11Session session)
    {
        Library = library;
        Slot = slot;
        _session = session;
    }

    /// <summary>The slot this workspace is authenticated against.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>The library that hosts this workspace. The workspace does not own the library.</summary>
    public Pkcs11Library Library { get; }

    /// <summary>Internal accessor for the underlying session. Used by <c>Pkcs11Key</c> to delegate operations.</summary>
    internal Pkcs11Session Session => _session;

    /// <summary>
    /// Asks the workspace's effective <see cref="Policy"/> whether it would allow <paramref name="request"/>,
    /// without throwing or logging. For choosing between alternatives up front — for example a BCL
    /// adapter picking the first cipher mode the policy accepts.
    /// </summary>
    /// <param name="request">The operation to evaluate.</param>
    /// <returns><see langword="true"/> when the policy allows it.</returns>
    /// <exception cref="ObjectDisposedException">The workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is null.</exception>
    public bool IsPermitted(PolicyRequest request)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        return _session.IsPermitted(request);
    }

    /// <summary>
    /// Submits <paramref name="request"/> to the workspace's effective <see cref="Policy"/> and throws
    /// when it is refused, logging the refusal as every built-in operation does. For code that makes a
    /// security-relevant choice the token never sees — for example the hash a managed pre-hashing step
    /// uses before a raw on-token signature — so that choice meets the same policy as the rest.
    /// </summary>
    /// <param name="request">The operation to check.</param>
    /// <exception cref="ObjectDisposedException">The workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is null.</exception>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the request.</exception>
    public void EnsurePermitted(PolicyRequest request)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        _session.Enforce(request);
    }

    /// <summary>
    /// The crypto policy currently enforced by this workspace: the one it was opened with, unless a
    /// <see cref="UsePolicy"/> lease is active.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The workspace has been disposed.</exception>
    public ICryptoPolicy Policy
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _session.Policy;
        }
    }

    /// <summary>
    /// Enforces <paramref name="policy"/> until the returned lease is disposed. Logged as a warning. Scope it to the operation that needs it:
    /// <code>using (workspace.UsePolicy(CryptoPolicy.AllowInsecure)) { /* one legacy operation */ }</code>
    /// Open leases form a stack: the most recently opened lease still open decides the policy, and the
    /// workspace's own policy applies once none is open. Disposing a lease withdraws only that lease, so
    /// disposing them out of order never re-instates a policy whose lease is already closed. The override
    /// applies to the whole workspace, not per thread.
    /// </summary>
    /// <param name="policy">The policy to enforce within the lease.</param>
    /// <returns>A lease that withdraws this override when disposed (idempotent).</returns>
    /// <exception cref="ObjectDisposedException">The workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="policy"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The workspace was opened under a policy whose
    /// <see cref="ICryptoPolicy.AllowsOverride"/> is false (for example <c>CryptoPolicy.NistApproved</c>).</exception>
    public IDisposable UsePolicy(ICryptoPolicy policy)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _session.UsePolicy(policy);
    }

    /// <summary>
    /// Returns a snapshot of the underlying session's state (slot, session state, flags, and the
    /// device-specific error code), as reported by <c>C_GetSessionInfo</c>.
    /// </summary>
    /// <returns>A <see cref="SessionInfo"/> describing the current session.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if the underlying <c>C_GetSessionInfo</c> call fails.</exception>
    public SessionInfo GetSessionInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _session.GetSessionInfo();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;

        // Explicitly log out before closing the session so the token's audit log records a
        // logout, not just a session close. Best-effort: the caller may have already logged out
        // (CKR_USER_NOT_LOGGED_IN), or the library/session may already be torn down — none of
        // those should make disposal throw. C_Logout affects the whole application's login state
        // on the slot, which is the intended end-of-context behaviour for an owned workspace.
        try
        {
            _session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // Already logged out, session/library already gone, or token rejected the logout
            // during teardown — disposal proceeds regardless.
        }

        _session.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Looks up a key by CKA_LABEL. If a matching private key is found, attempts to
    /// pair it with its public companion via CKA_ID; if the lookup hits a symmetric key
    /// (or a private key with no companion), the returned <see cref="Pkcs11Key"/> carries
    /// a single handle.
    /// </summary>
    /// <param name="label">The CKA_LABEL string to match.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public Pkcs11Key OpenKey(string label)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(label);

        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return OpenKeyByFilter(filter, $"label '{label}'");
    }

    /// <summary>
    /// Looks up a key by CKA_ID.
    /// </summary>
    /// <param name="id">The CKA_ID bytes to match.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public Pkcs11Key OpenKey(ReadOnlySpan<byte> id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (id.IsEmpty) throw new ArgumentException("Id must not be empty.", nameof(id));

        using var filter = ObjectTemplate.Empty().Id(id).Build();
        return OpenKeyByFilter(filter, $"id (len={id.Length})");
    }

    /// <summary>
    /// Finds all keys matching the given template.
    /// </summary>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A list of <see cref="Pkcs11Key"/>. May be empty. The list owns the keys: dispose it
    /// (a <c>using</c> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Key> FindKeys(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _session.FindAllObjects([.. filter.Attributes]);
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
    /// it (a <c>using</c> will do) to release them all. Disposal does not destroy anything on the token.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Object> FindObjects(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _session.FindAllObjects([.. filter.Attributes]);
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
    /// dispose it (a <c>using</c> will do) to release them all.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if a certificate's
    /// <c>CKA_VALUE</c> cannot be read; also propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public ReadOnlyDisposableList<Pkcs11Certificate> FindCertificates()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_CERTIFICATE)
            .Build();

        var handles = _session.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Certificate>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateCertificateFromHandle(handle));
        return new ReadOnlyDisposableList<Pkcs11Certificate>(result);
    }

    private Pkcs11Certificate HydrateCertificateFromHandle(ObjectHandle handle)
    {
        using var attrs = _session.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID]);
        if (attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "FindCertificates (CKA_VALUE unreadable)");

        var certificate = X509CertificateLoader.LoadCertificate(attrs[0].GetValueAsByteArray());
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
        return new Pkcs11Certificate(this, handle, label, id, certificate);
    }

    /// <summary>
    /// Finds the private-key object with the given <c>CKA_ID</c> and hydrates it (pairing its
    /// public companion). Returns <c>null</c> when <paramref name="id"/> is empty or no matching
    /// private key exists. Filters on <c>CKA_CLASS = CKO_PRIVATE_KEY</c> so it never matches the
    /// certificate (which shares the id). Used by <see cref="Pkcs11Certificate"/>.
    /// </summary>
    internal Pkcs11Key? TryOpenPrivateKey(byte[] id)
    {
        if (id.Length == 0) return null;

        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY)
            .Id(id)
            .Build();

        var handles = _session.FindAllObjects([.. filter.Attributes]);
        return handles.Count == 0 ? null : HydrateKeyFromHandle(handles[0]);
    }

    private Pkcs11Object HydrateObjectFromHandle(ObjectHandle handle)
    {
        using var attrs = _session.GetAttributeValue(handle, [CKA.CKA_CLASS, CKA.CKA_LABEL, CKA.CKA_ID]);
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
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_CreateObject</c> call.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the template sets <c>CKA_SENSITIVE=false</c> and the workspace's <see cref="Policy"/> refuses it.</exception>
    public Pkcs11Key ImportKey(ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(template);

        var handle = _session.CreateObject([.. template.Attributes]);
        return HydrateKeyFromHandle(handle);
    }

    /// <summary>
    /// Generates a new symmetric key using <c>C_GenerateKey</c> and returns it as a
    /// <see cref="Pkcs11Key"/>. For asymmetric key generation, use the two-template
    /// overload.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is on the library's insecure-mechanism list and the workspace's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateKey(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        var handle = _session.GenerateKey(mechanism, [.. template.Attributes]);
        return HydrateKeyFromHandle(handle);
    }

    /// <summary>
    /// Runs a password-based KDF on the token and copies its output into <paramref name="destination"/>.
    /// For a protocol that needs the derived bytes in managed code.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This exports key material.</b> The <see cref="Policy"/> decides it as a
    /// <see cref="SecretExportRequest"/> of <see cref="SecretExportKind.PasswordKdfOutput"/>,
    /// which <c>CryptoPolicy.Recommended</c> refuses unless widened for it. When the derived key can stay
    /// on the token, use <see cref="GenerateKey(Mechanism, ObjectTemplate)"/> with a sensitive template.
    /// </para>
    /// <para>
    /// Only <c>CKM_PKCS5_PBKD2</c> with <see cref="CkmPkcs5Pbkd2Params"/> is supported. The output passes
    /// through an ephemeral session key the library creates — generic secret, extractable, not
    /// sensitive, not copyable, no usage — and destroys before this returns, whether it
    /// succeeds or not. That template is covered by the export decision and not judged again as a key
    /// template; the mechanism is still judged. On failure, <paramref name="destination"/> is zeroed.
    /// </para>
    /// </remarks>
    /// <param name="mechanism"><c>CKM_PKCS5_PBKD2</c> with its parameters.</param>
    /// <param name="destination">Receives the derived bytes; its length is the length derived.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is empty, or <paramref name="mechanism"/> is not <c>CKM_PKCS5_PBKD2</c> with <see cref="CkmPkcs5Pbkd2Params"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the <see cref="Policy"/> refuses the export or the mechanism.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose the derived value or produces one of another length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c> call.</exception>
    public void DeriveAndExportSecret(Mechanism mechanism, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        if (destination.IsEmpty)
            throw new ArgumentException("The buffer must not be empty.", nameof(destination));
        SecretExportKind kind = SecretExport.Classify(SecretExport.Operation.Generate, mechanism, nameof(mechanism));

        using IDisposable export = SecretExport.Authorize(_session, kind, mechanism.Type, baseKeyClass: null, baseKeyType: null);

        SecretExport.Export(_session, destination.Length,
            template => _session.GenerateKey(mechanism, template, kind),
            destination);
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
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/>, <paramref name="publicKeyTemplate"/>, or <paramref name="privateKeyTemplate"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="publicKeyTemplate"/> sets a <c>CKA_CLASS</c> other than <see cref="CKO.CKO_PUBLIC_KEY"/>, or <paramref name="privateKeyTemplate"/> one other than <see cref="CKO.CKO_PRIVATE_KEY"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure, or the requested key strength is below the secure-defaults baseline, and the workspace's <see cref="Policy"/> refuses it.</exception>
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

        _session.GenerateKeyPair(
            mechanism,
            [.. publicKeyTemplate.Attributes],
            [.. privateKeyTemplate.Attributes],
            out var publicHandle,
            out var privateHandle);

        // Read identifying metadata off the private side — we already have both
        // handles in hand so we bypass the companion-discovery lookup.
        using var attrs = _session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        ]);
        var keyType = (CKK)attrs[0].GetValueAsUlong();
        string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
        byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();

        return new Pkcs11Key(
            workspace: this,
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

    // === Secure-default key-generation helpers =============================

    /// <summary>
    /// Generates an AES secret key — sensitive, non-extractable, usable for encryption and
    /// decryption only. Session-only unless <paramref name="persistOnToken"/> is set.
    /// </summary>
    /// <remarks>
    /// Deliberately does not grant <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c>: a key that can both decrypt
    /// caller-supplied ciphertext and wrap other keys is a wrap-oracle (wrap an extractable key,
    /// then decrypt the blob to read it in the clear) and an unwrap-injection vector (encrypt a
    /// chosen plaintext, then unwrap it as a "wrapped key" of known value). Use
    /// <see cref="GenerateAesKeyEncryptionKey"/> for a dedicated, wrap/unwrap-only KEK.
    /// </remarks>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to the key. Default none.</param>
    /// <param name="persistOnToken">If true, the key is a token object (<c>CKA_TOKEN=true</c>, persistent). Default false (session-only).</param>
    /// <returns>The generated AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="bitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateAesKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), AesKeyLengthMessage);

        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(bitLength / 8)
            .Sensitive().NonExtractable()
            .Encrypt().Decrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
            builder = builder.Label(label);

        using var template = builder.Build();
        var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an AES key-encryption key (KEK) — sensitive, non-extractable, usable only to wrap
    /// and unwrap other keys via <see cref="Pkcs11Key.Wrap"/>/<see cref="Pkcs11Key.Unwrap"/>.
    /// Session-only unless <paramref name="persistOnToken"/> is set.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — see <see cref="GenerateAesKey"/>
    /// for why combining data-encryption and key-wrapping roles on one key is a wrap-oracle risk.
    /// Every key unwrapped through this KEK is forced sensitive/non-extractable via
    /// <c>CKA_UNWRAP_TEMPLATE</c>, regardless of what the caller's unwrap template requests; this
    /// KEK will only wrap keys already marked <c>CKA_SENSITIVE</c> via <c>CKA_WRAP_TEMPLATE</c>.
    /// </remarks>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to the key. Default none.</param>
    /// <param name="persistOnToken">If true, the key is a token object (<c>CKA_TOKEN=true</c>, persistent). Default false (session-only).</param>
    /// <returns>The generated AES key-encryption key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="bitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateAesKeyEncryptionKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), AesKeyLengthMessage);

        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(bitLength / 8)
            .Sensitive().NonExtractable()
            .Wrap().Unwrap()
            .WrapTemplate(t => t.Sensitive())
            .UnwrapTemplate(t => t.Sensitive().NonExtractable())
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
            builder = builder.Label(label);

        using var template = builder.Build();
        var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an RSA signing key pair. The private key is sensitive, non-extractable, and usable
    /// only for signing; the public key only for verification. The public exponent is fixed at
    /// 65537. The returned key carries both handles.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — see
    /// <see cref="GenerateRsaKeyTransportKeyPair"/> for a dedicated encryption pair, and for why
    /// combining signing and encryption roles on one RSA key pair is unsafe.
    /// </remarks>
    /// <param name="modulusBits">RSA modulus size in bits. Default 4096. Sizes below 2048 (NIST SP
    /// 800-131A) are refused unless the workspace's <see cref="Policy"/> permits it.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated RSA key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="modulusBits"/> is not positive.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="modulusBits"/> is &lt; 2048 and the workspace's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateRsaSigningKeyPair(int modulusBits = 4096, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulusBits);
        // The sub-2048 secure-defaults gate is enforced once in the session layer's crypto policy check,
        // so it applies uniformly to this helper and to direct low-level GenerateKey callers.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01])
            .Verify()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable()
            .Sign()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }

    /// <summary>
    /// Generates an RSA key-transport key pair. The private key is sensitive, non-extractable, and
    /// usable only to decrypt; the public key only to encrypt (RSA-OAEP key transport). The public
    /// exponent is fixed at 65537. The returned key carries both handles.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_SIGN</c>/<c>CKA_VERIFY</c> and <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c>
    /// — see <see cref="GenerateRsaSigningKeyPair"/> for the signing counterpart. A caller who
    /// specifically needs RSA <c>C_WrapKey</c>/<c>C_UnwrapKey</c> semantics (rather than encrypting
    /// data directly) should build that template explicitly via
    /// <see cref="GenerateKeyPair(Mechanism, ObjectTemplate, ObjectTemplate)"/>.
    /// </remarks>
    /// <param name="modulusBits">RSA modulus size in bits. Default 4096. Sizes below 2048 (NIST SP
    /// 800-131A) are refused unless the workspace's <see cref="Policy"/> permits it.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated RSA key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="modulusBits"/> is not positive.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="modulusBits"/> is &lt; 2048 and the workspace's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateRsaKeyTransportKeyPair(int modulusBits = 4096, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulusBits);
        // The sub-2048 secure-defaults gate is enforced once in the session layer's crypto policy check,
        // so it applies uniformly to this helper and to direct low-level GenerateKey callers.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01])
            .Encrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable()
            .Decrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }

    /// <summary>
    /// Generates an EC key pair on a NIST prime curve. The private key is sensitive,
    /// non-extractable, and usable for signing and ECDH derivation.
    /// </summary>
    /// <param name="curve">Named curve from <see cref="Pkcs11ECCurve.NamedCurves"/> (or <see cref="Pkcs11ECCurve.CreateFromValue(string, string?)"/>).
    /// Defaults to <see cref="Pkcs11ECCurve.NamedCurves.NistP256"/> when omitted. The token must support the curve.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated EC key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="curve"/> is the default (uninitialized) <see cref="Pkcs11ECCurve"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's <see cref="Policy"/> does not allow
    /// the curve (under the default policy: any curve not on its allow-list, including every curve below
    /// 128-bit security).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateEcKeyPair(Pkcs11ECCurve? curve = null, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Pkcs11ECCurve resolved = curve ?? Pkcs11ECCurve.NamedCurves.NistP256;
        if (resolved.IsDefault)
            throw new ArgumentException("An EC curve must be specified.", nameof(curve));
        // The curve allow-list is enforced by the session's GenerateKeyPair, which every EC key-pair
        // generation reaches, so there is no separate check here.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(resolved.GetEcParams())
            .Verify()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Sensitive().NonExtractable()
            .Sign().Derive()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }

    /// <summary>
    /// Performs ECDH1 key agreement using <paramref name="ecPrivateKey"/> and the peer's public
    /// point, deriving an AES secret key on the token. The derived key is session-only, sensitive,
    /// non-extractable, and non-modifiable — suitable for use with AES-GCM.
    /// </summary>
    /// <remarks>
    /// When <paramref name="ecPrivateKey"/> is on one of the library's catalog curves, the peer point is
    /// checked against that curve before it reaches the token, as on every ECDH derivation: it must be an uncompressed point of the curve's field size
    /// that satisfies the curve equation. PKCS#11 does not require the token to check either, and
    /// skipping both is the invalid-curve / small-subgroup attack, which recovers a token-resident
    /// private key one residue at a time. The raw point carries no curve name, so a peer that claims
    /// another curve cannot be told apart here; the <see cref="ECParameters"/> overload also refuses that.
    /// </remarks>
    /// <param name="ecPrivateKey">The caller's EC private key (must have <c>CKA_DERIVE=true</c>).</param>
    /// <param name="peerPublicPoint">The peer's uncompressed public EC point, as a DER OCTET STRING (the full <c>CKA_EC_POINT</c> value) or raw.</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="kdf">KDF applied to the raw ECDH shared secret before it becomes the derived AES
    /// key's material. Default <see cref="CKD.CKD_SHA256_KDF"/>. <see cref="CKD.CKD_NULL"/> applies no
    /// KDF at all — the token's own truncation/expansion of the raw x-coordinate becomes the AES key
    /// material directly, which NIST SP 800-56A forbids; this method never returns the raw secret for
    /// an off-token KDF step, since the result is always an on-token, non-extractable key. Requires
    /// a policy that permits it (see <see cref="Policy"/>). Some tokens (e.g. SoftHSM 2.x) implement only <c>CKD_NULL</c>.</param>
    /// <returns>The derived AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="ecPrivateKey"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicPoint"/> is empty, is not an uncompressed point of the curve's field size, or does not satisfy the curve equation.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="aesBitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="kdf"/> is not on the workspace's <see cref="Policy"/> KDF allow-list (under the default policy this includes <see cref="CKD.CKD_NULL"/> and the SHA-1 / SHA-224 KDFs).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key DeriveSharedSecretEcdh(
        Pkcs11Key ecPrivateKey,
        ReadOnlySpan<byte> peerPublicPoint,
        int aesBitLength = 256,
        CKD kdf = CKD.CKD_SHA256_KDF)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ecPrivateKey);
        if (aesBitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), AesKeyLengthMessage);
        return DeriveSharedSecretEcdhCore(ecPrivateKey, new CkmEcdh1DeriveParams(kdf, peerPublicPoint), aesBitLength, nameof(peerPublicPoint));
    }

    /// <summary>
    /// Performs ECDH1 key agreement using <paramref name="ecPrivateKey"/> and the peer's public key,
    /// deriving an AES secret key on the token. The derived key is session-only, sensitive,
    /// non-extractable, and non-modifiable — suitable for use with AES-GCM.
    /// </summary>
    /// <remarks>
    /// Validates <paramref name="peerPublicKey"/> before it reaches the token: it must be on the
    /// same curve as <paramref name="ecPrivateKey"/>, its coordinates must match that curve's field
    /// size, and the point must satisfy the curve equation. See
    /// <see cref="DeriveSharedSecretEcdh(Pkcs11Key, ReadOnlySpan{byte}, int, CKD)"/> for why that
    /// matters (invalid-curve / small-subgroup recovery of the token-resident private key).
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
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="ecPrivateKey"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicKey"/> has no X or Y coordinate, its curve does not match <paramref name="ecPrivateKey"/>'s, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="aesBitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="kdf"/> is not on the workspace's <see cref="Policy"/> KDF allow-list (under the default policy this includes <see cref="CKD.CKD_NULL"/> and the SHA-1 / SHA-224 KDFs).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key DeriveSharedSecretEcdh(
        Pkcs11Key ecPrivateKey,
        ECParameters peerPublicKey,
        int aesBitLength = 256,
        CKD kdf = CKD.CKD_SHA256_KDF)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ecPrivateKey);
        if (aesBitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), AesKeyLengthMessage);

        return DeriveSharedSecretEcdhCore(ecPrivateKey, CkmEcdh1DeriveParams.ForPeer(kdf, peerPublicKey), aesBitLength, nameof(peerPublicKey));
    }

    // Both overloads: the session enforces the KDF allow-list and checks the peer against the key's
    // curve on the derive below, as on every ECDH derivation.
    private static Pkcs11Key DeriveSharedSecretEcdhCore(Pkcs11Key ecPrivateKey, CkmEcdh1DeriveParams parameters, int aesBitLength, string peerParamName)
    {
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, parameters);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(aesBitLength / 8)
            .Sensitive().NonExtractable()
            .Encrypt().Decrypt()
            .OnToken(false)
            .Attribute(CKA.CKA_MODIFIABLE, false)
            .Build();
        return ecPrivateKey.DeriveCore(mechanism, template, peerParamName);
    }

    /// <summary>
    /// Reads <paramref name="length"/> bytes from the token's RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate. Must be &gt; 0.</param>
    /// <returns>A newly allocated byte array of length <paramref name="length"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateRandom</c> call.</exception>
    public byte[] GenerateRandom(int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        return _session.GenerateRandom(length);
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
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateRandom</c> call.</exception>
    public void GenerateRandom(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _session.GenerateRandom(destination);
    }

    /// <summary>
    /// Seeds the token's RNG with the supplied bytes. Optional — many tokens ignore seed
    /// data because they use hardware entropy.
    /// </summary>
    /// <param name="seed">Seed bytes. Must not be empty.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="seed"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_SeedRandom</c> call.</exception>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (seed.IsEmpty)
            throw new ArgumentException("Seed must not be empty.", nameof(seed));
        _session.SeedRandom(seed);
    }

    /// <summary>
    /// Changes the logged-in user's PIN via <c>C_SetPIN</c>. The session must be authenticated as
    /// the user (or SO) whose PIN is being changed.
    /// </summary>
    /// <param name="oldPin">The current PIN.</param>
    /// <param name="newPin">The replacement PIN.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="oldPin"/> or <paramref name="newPin"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change (e.g. wrong old PIN, policy violation).</exception>
    public void SetPinWithPin(SecurePin oldPin, SecurePin newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        _session.SetPin(oldPin, newPin);
    }

    /// <summary>
    /// Changes the logged-in user's PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Both the old and new PIN are entered on
    /// the device; PKCS#11 signals this by calling <c>C_SetPIN</c> with both PIN pointers
    /// <c>NULL_PTR</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the change.</exception>
    public void SetPinWithPinpad()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _session.SetPin();
    }

    /// <summary>
    /// Initializes the normal user's PIN via <c>C_InitPIN</c>. Requires a session authenticated as
    /// the Security Officer (SO).
    /// </summary>
    /// <param name="userPin">The user PIN to set.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="userPin"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the operation (e.g. not logged in as SO).</exception>
    public void InitPinWithPin(SecurePin userPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(userPin);
        _session.InitPin(userPin);
    }

    /// <summary>
    /// Initializes the normal user's PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Requires a session authenticated as the
    /// Security Officer (SO); PKCS#11 signals on-device entry by calling <c>C_InitPIN</c> with
    /// <c>pPin = NULL_PTR</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the operation (e.g. not logged in as SO).</exception>
    public void InitPinWithPinpad()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _session.InitPin();
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is a broken digest (e.g. <see cref="CKM.CKM_MD5"/> or <see cref="CKM.CKM_SHA_1"/>) and the workspace's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Digest</c> call.</exception>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        return _session.Digest(mechanism, data);
    }

    /// <summary>
    /// Hydrates an existing object handle into a Pkcs11Key (used after operations that
    /// produce a new on-token object — Unwrap, Derive).
    /// </summary>
    internal Pkcs11Key HydrateExistingHandleAsKey(ObjectHandle handle)
        => HydrateKeyFromHandle(handle);

    private ObjectHandle FindCompanion(CKO companionClass, byte[] id)
    {
        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)companionClass)
            .Id(id)
            .Build();
        var handles = _session.FindAllObjects([.. filter.Attributes]);
        return handles.Count > 0 ? handles[0] : ObjectHandle.Invalid;
    }

    private Pkcs11Key OpenKeyByFilter(ObjectTemplate filter, string queryDescription)
    {
        var handles = _session.FindAllObjects([.. filter.Attributes]);
        if (handles.Count == 0)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                $"OpenKey({queryDescription})");

        return HydrateKeyFromHandle(handles[0]);
    }

    /// <summary>
    /// Reads CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID off the handle and constructs a
    /// <see cref="Pkcs11Key"/>. If the handle is a private key with a non-empty CKA_ID,
    /// searches for a matching public companion and attaches both handles.
    /// </summary>
    private Pkcs11Key HydrateKeyFromHandle(ObjectHandle handle)
    {
        using var attrs = _session.GetAttributeValue(handle,
        [
            CKA.CKA_CLASS,
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        ]);
        var objectClass = (CKO)attrs[0].GetValueAsUlong();
        var keyType = (CKK)attrs[1].GetValueAsUlong();
        string? label = attrs[2].CannotBeRead ? null : attrs[2].GetValueAsString();
        byte[] id = attrs[3].CannotBeRead ? [] : attrs[3].GetValueAsByteArray();

        ObjectHandle privateHandle = ObjectHandle.Invalid;
        ObjectHandle publicHandle = ObjectHandle.Invalid;

        if (objectClass == CKO.CKO_PRIVATE_KEY)
        {
            privateHandle = handle;
            // Search for public companion by CKA_ID. Empty ID disables the lookup.
            if (id.Length > 0)
                publicHandle = FindCompanion(CKO.CKO_PUBLIC_KEY, id);
        }
        else if (objectClass == CKO.CKO_PUBLIC_KEY)
        {
            publicHandle = handle;
            // Mirror the private-side lookup. FindAllObjects orders pub/priv arbitrarily
            // — if the public came back first, we must still hydrate the private half so
            // Sign/Decrypt work. Empty ID disables the lookup (no reliable way to match).
            if (id.Length > 0)
                privateHandle = FindCompanion(CKO.CKO_PRIVATE_KEY, id);
        }
        else // CKO_SECRET_KEY or other
        {
            privateHandle = handle;
        }

        return new Pkcs11Key(
            workspace: this,
            privateHandle: privateHandle,
            publicHandle: publicHandle,
            keyType: keyType,
            label: label,
            id: id);
    }
}
