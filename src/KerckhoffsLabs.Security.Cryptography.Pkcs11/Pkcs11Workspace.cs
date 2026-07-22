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
/// Construction is exclusively via <see cref="Pkcs11Library.OpenWorkspace(string, CKU, SecurePin)"/>.
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
    /// When <c>true</c>, operations on this workspace that use mechanisms the library considers
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, raw MD5/SHA-1, and the ML-KEM
    /// extract-and-destroy path) are no longer rejected with <see cref="InsecureOperationException"/>.
    /// Default is <c>false</c>. Enabling it logs a warning. Prefer <see cref="AllowInsecureScope"/>
    /// to opt in for a single operation rather than latching the flag on for the workspace lifetime.
    /// </summary>
    public bool AllowInsecure
    {
        get => _session.AllowInsecure;
        set => _session.AllowInsecure = value;
    }

    /// <summary>
    /// Enables <see cref="AllowInsecure"/> for the duration of the returned lease and restores the
    /// previous value on dispose. Scopes the insecure opt-in to a single operation:
    /// <code>using (workspace.AllowInsecureScope()) { /* one insecure op */ }</code>
    /// Nested scopes restore in LIFO order.
    /// </summary>
    public IDisposable AllowInsecureScope() => _session.AllowInsecureScope();

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
    /// <returns>A list of <see cref="Pkcs11Key"/>. May be empty. Caller disposes each.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public IReadOnlyList<Pkcs11Key> FindKeys(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _session.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Key>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateKeyFromHandle(handle));
        return result;
    }

    /// <summary>
    /// Finds all token objects matching the given template, regardless of class — certificates,
    /// data objects, keys, etc. Unlike <see cref="FindKeys"/> (which is key-only and reads
    /// <c>CKA_KEY_TYPE</c>), this returns a general <see cref="Pkcs11Object"/> view exposing the
    /// object class and its <c>CKA_VALUE</c>.
    /// </summary>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder
    /// (e.g. filter on <c>CKA_CLASS = CKO_CERTIFICATE</c>).</param>
    /// <returns>A list of <see cref="Pkcs11Object"/>. May be empty. Caller disposes each.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="filter"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public IReadOnlyList<Pkcs11Object> FindObjects(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _session.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Object>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateObjectFromHandle(handle));
        return result;
    }

    /// <summary>
    /// Finds all certificate objects on the token (<c>CKA_CLASS = CKO_CERTIFICATE</c>) — a typed
    /// counterpart to <see cref="FindKeys"/>. Each <see cref="Pkcs11Certificate"/> exposes the
    /// parsed <see cref="X509Certificate2"/> and bridges to its on-token private key by
    /// <c>CKA_ID</c>.
    /// </summary>
    /// <returns>A list of <see cref="Pkcs11Certificate"/>. May be empty. Caller disposes each.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if a certificate's
    /// <c>CKA_VALUE</c> cannot be read; also propagated from the underlying <c>C_FindObjects</c> call.</exception>
    public IReadOnlyList<Pkcs11Certificate> FindCertificates()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_CERTIFICATE)
            .Build();

        var handles = _session.FindAllObjects([.. filter.Attributes]);
        var result = new List<Pkcs11Certificate>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateCertificateFromHandle(handle));
        return result;
    }

    private Pkcs11Certificate HydrateCertificateFromHandle(ObjectHandle handle)
    {
        var attrs = _session.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID]);
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "FindCertificates (CKA_VALUE unreadable)");

            var certificate = X509CertificateLoader.LoadCertificate(attrs[0].GetValueAsByteArray());
            string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
            byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
            return new Pkcs11Certificate(this, handle, label, id, certificate);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
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
        var attrs = _session.GetAttributeValue(handle, [CKA.CKA_CLASS, CKA.CKA_LABEL, CKA.CKA_ID]);
        try
        {
            var objectClass = (CKO)attrs[0].GetValueAsUlong();
            string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
            byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();
            return new Pkcs11Object(this, handle, objectClass, label, id);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
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
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is on the library's insecure-mechanism list and <see cref="AllowInsecure"/> is false.</exception>
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
    /// Generates a new asymmetric key pair using <c>C_GenerateKeyPair</c> and returns
    /// it as a single <see cref="Pkcs11Key"/> carrying both handles.
    /// </summary>
    /// <param name="mechanism">Key-pair generation mechanism (e.g. <see cref="CKM.CKM_RSA_PKCS_KEY_PAIR_GEN"/>).</param>
    /// <param name="privateTemplate">Template for the private key half.</param>
    /// <param name="publicTemplate">Template for the public key half.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/>, <paramref name="privateTemplate"/>, or <paramref name="publicTemplate"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure, or the requested key strength is below the secure-defaults baseline, and <see cref="AllowInsecure"/> is false.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateKey(
        Mechanism mechanism,
        ObjectTemplate privateTemplate,
        ObjectTemplate publicTemplate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(privateTemplate);
        ArgumentNullException.ThrowIfNull(publicTemplate);

        _session.GenerateKeyPair(
            mechanism,
            [.. publicTemplate.Attributes],
            [.. privateTemplate.Attributes],
            out var publicHandle,
            out var privateHandle);

        // Read identifying metadata off the private side — we already have both
        // handles in hand so we bypass the companion-discovery lookup.
        var attrs = _session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        ]);

        try
        {
            var keyType = (CKK)attrs[0].GetValueAsUlong();
            string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
            byte[] id = attrs[2].CannotBeRead ? [] : attrs[2].GetValueAsByteArray();

            return new Pkcs11Key(
                workspace: this,
                privateHandle: privateHandle,
                publicHandle: publicHandle,
                keyType: keyType,
                label: label,
                id: id,
                ownedLibrary: null,
                ownsWorkspace: false);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    // === Secure-default key-generation helpers =============================

    /// <summary>
    /// Generates an AES secret key — sensitive, non-extractable, usable for encryption,
    /// decryption, and key wrapping. Session-only unless <paramref name="persistOnToken"/> is set.
    /// </summary>
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
            throw new ArgumentOutOfRangeException(nameof(bitLength), "AES key length must be 128, 192, or 256 bits.");

        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(bitLength / 8)
            .Sensitive().NonExtractable()
            .Encrypt().Decrypt().Wrap().Unwrap()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
            builder = builder.Label(label);

        using var template = builder.Build();
        using var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an RSA key pair. The private key is sensitive and non-extractable; the public
    /// exponent is fixed at 65537. The returned key carries both handles.
    /// </summary>
    /// <param name="modulusBits">RSA modulus size in bits. Default 4096. Sizes below 2048 (NIST SP
    /// 800-131A) are refused unless <see cref="AllowInsecure"/> is set.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated RSA key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="modulusBits"/> is not positive.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="modulusBits"/> is &lt; 2048 and <see cref="AllowInsecure"/> is false.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateRsaKeyPair(int modulusBits = 4096, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulusBits);
        // The sub-2048 secure-defaults gate is enforced once in the session layer (GuardKeyPairStrength),
        // so it applies uniformly to this helper and to direct low-level GenerateKey callers.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01])
            .Encrypt().Verify().Wrap()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable()
            .Sign().Decrypt().Unwrap()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        return GenerateKey(mechanism, privTemplate, pubTemplate);
    }

    /// <summary>
    /// Generates an EC key pair on a NIST prime curve. The private key is sensitive,
    /// non-extractable, and usable for signing and ECDH derivation.
    /// </summary>
    /// <param name="curve">Named curve from <see cref="ECCurve.NamedCurves"/> (or <see cref="ECCurve.CreateFromValue(string, string?)"/>).
    /// Defaults to <see cref="ECCurve.NamedCurves.NistP256"/> when omitted. The token must support the curve.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated EC key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="curve"/> is the default (uninitialized) <see cref="ECCurve"/>.</exception>
    /// <exception cref="InsecureOperationException">The curve provides less than 128-bit
    /// security (the 160/192/224-bit NIST and Brainpool curves) and <see cref="AllowInsecure"/> is false.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateEcKeyPair(ECCurve? curve = null, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ECCurve resolved = curve ?? ECCurve.NamedCurves.NistP256;
        if (resolved.IsDefault)
            throw new ArgumentException("An EC curve must be specified.", nameof(curve));
        if (resolved.IsBelowSecurityBaseline && !AllowInsecure)
            throw new InsecureOperationException(
                $"EC curve {resolved} provides less than 128-bit security. Use NistP256 or stronger, " +
                "or set Pkcs11Workspace.AllowInsecure = true for legacy interop.");

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(resolved.GetEcParams())
            .Verify()
            .Encrypt(false).Wrap(false)
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
        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        return GenerateKey(mechanism, privTemplate, pubTemplate);
    }

    /// <summary>
    /// Performs ECDH1 key agreement using <paramref name="ecPrivateKey"/> and the peer's public
    /// point, deriving an AES secret key on the token. The derived key is session-only, sensitive,
    /// non-extractable, and non-modifiable — suitable for use with AES-GCM.
    /// </summary>
    /// <param name="ecPrivateKey">The caller's EC private key (must have <c>CKA_DERIVE=true</c>).</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value).</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="kdf">KDF applied to the raw ECDH shared secret. Default <see cref="CKD.CKD_SHA256_KDF"/>;
    /// pass <see cref="CKD.CKD_NULL"/> to take the raw shared secret as the key material (do your own KDF off-token).
    /// Some tokens (e.g. SoftHSM 2.x) implement only <c>CKD_NULL</c>.</param>
    /// <returns>The derived AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="ecPrivateKey"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="aesBitLength"/> is not 128, 192, or 256.</exception>
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
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), "AES key length must be 128, 192, or 256 bits.");

        using var p = new CkmEcdh1DeriveParams(kdf, peerPublicPoint);
        using var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);
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
    public void SetPin(SecurePin oldPin, SecurePin newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        _session.SetPin(oldPin, newPin);
    }

    /// <summary>
    /// Initializes the normal user's PIN via <c>C_InitPIN</c>. Requires a session authenticated as
    /// the Security Officer (SO).
    /// </summary>
    /// <param name="userPin">The user PIN to set.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="userPin"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">The token rejected the operation (e.g. not logged in as SO).</exception>
    public void InitPin(SecurePin userPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(userPin);
        _session.InitPin(userPin);
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the workspace has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is a broken digest (e.g. <see cref="CKM.CKM_MD5"/> or <see cref="CKM.CKM_SHA_1"/>) and <see cref="AllowInsecure"/> is false.</exception>
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
        var attrs = _session.GetAttributeValue(handle,
        [
            CKA.CKA_CLASS,
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        ]);

        try
        {
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
                id: id,
                ownedLibrary: null,
                ownsWorkspace: false);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }
}
