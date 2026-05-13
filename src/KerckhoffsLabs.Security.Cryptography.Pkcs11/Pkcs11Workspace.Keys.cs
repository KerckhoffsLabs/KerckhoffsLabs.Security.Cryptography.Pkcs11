using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Workspace
{
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

        var handles = _session.FindAllObjects(filter.Attributes.ToList());
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

        var handle = _session.CreateObject(template.Attributes.ToList());
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

        var handle = _session.GenerateKey(mechanism, template.Attributes.ToList());
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
            publicTemplate.Attributes.ToList(),
            privateTemplate.Attributes.ToList(),
            out var publicHandle,
            out var privateHandle);

        // Read identifying metadata off the private side — we already have both
        // handles in hand so we bypass the companion-discovery lookup.
        var attrs = _session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        });

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
    /// Hydrates an existing object handle into a Pkcs11Key (used after operations that
    /// produce a new on-token object — Unwrap, Derive).
    /// </summary>
    internal Pkcs11Key HydrateExistingHandleAsKey(ObjectHandle handle)
        => HydrateKeyFromHandle(handle);

    private Pkcs11Key OpenKeyByFilter(ObjectTemplate filter, string queryDescription)
    {
        var handles = _session.FindAllObjects(filter.Attributes.ToList());
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
        var attrs = _session.GetAttributeValue(handle, new List<CKA>
        {
            CKA.CKA_CLASS,
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        });

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
                {
                    using var companionFilter = ObjectTemplate.Empty()
                        .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PUBLIC_KEY)
                        .Id(id)
                        .Build();
                    var companionHandles = _session.FindAllObjects(companionFilter.Attributes.ToList());
                    if (companionHandles.Count > 0)
                        publicHandle = companionHandles[0];
                }
            }
            else if (objectClass == CKO.CKO_PUBLIC_KEY)
            {
                publicHandle = handle;
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
