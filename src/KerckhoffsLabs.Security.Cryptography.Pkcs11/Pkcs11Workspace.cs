using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
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
/// <see cref="Pkcs11Library"/>. The workspace owns the session it opened and closes it
/// on <see cref="Dispose"/>; the session's own Dispose logs the user out before closing.
/// </para>
/// <para>
/// Keys obtained via the workspace's factory methods hold a non-owning reference to the
/// workspace. The workspace must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed class Pkcs11Workspace : IDisposable
{
    private readonly Pkcs11Library _library;
    private readonly Pkcs11Slot _slot;
    private readonly Pkcs11Session _session;
    private bool _disposed;

    internal Pkcs11Workspace(Pkcs11Library library, Pkcs11Slot slot, Pkcs11Session session)
    {
        _library = library;
        _slot = slot;
        _session = session;
    }

    /// <summary>The slot this workspace is authenticated against.</summary>
    public Pkcs11Slot Slot => _slot;

    /// <summary>The library that hosts this workspace. The workspace does not own the library.</summary>
    public Pkcs11Library Library => _library;

    /// <summary>Internal accessor for the underlying session. Used by <c>Pkcs11Key</c> to delegate operations.</summary>
    internal Pkcs11Session Session => _session;

    /// <summary>
    /// When <c>true</c>, operations on this workspace that use mechanisms the library considers
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, raw MD5/SHA-1, and the ML-KEM
    /// extract-and-destroy path) are no longer rejected with <see cref="Exceptions.InsecureOperationException"/>.
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

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
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
    /// <exception cref="ArgumentException">Thrown if <paramref name="id"/> is empty.</exception>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
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
    /// Creates a new object on the token from the given template and returns it as a
    /// <see cref="Pkcs11Key"/>. Used for importing pre-existing key material —
    /// <see cref="ObjectTemplate.ForSecretKey(CKK)"/> with <c>.Value(...)</c> for
    /// symmetric keys, or analogous templates for public/private RSA/EC keys.
    /// </summary>
    /// <param name="template">A fully-built template. Will not be modified.</param>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the created object.</returns>
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
            byte[] id = attrs[2].CannotBeRead ? Array.Empty<byte>() : attrs[2].GetValueAsByteArray();

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

    /// <summary>
    /// Reads <paramref name="length"/> bytes from the token's RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate. Must be &gt; 0.</param>
    /// <returns>A newly allocated byte array of length <paramref name="length"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
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
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (seed.IsEmpty)
            throw new ArgumentException("Seed must not be empty.", nameof(seed));
        _session.SeedRandom(seed);
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
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
            byte[] id = attrs[3].CannotBeRead ? Array.Empty<byte>() : attrs[3].GetValueAsByteArray();

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
