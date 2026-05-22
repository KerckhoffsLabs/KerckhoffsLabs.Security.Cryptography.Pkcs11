using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A general view over a single PKCS#11 token object — certificate, data object, or any other
/// class — returned by <see cref="Pkcs11Workspace.FindObjects(Objects.ObjectTemplate)"/>. Exposes
/// the object class, label/id, and the raw <c>CKA_VALUE</c> payload. For key-specific operations
/// (sign/verify/encrypt/wrap/…) use <see cref="Pkcs11Key"/> via the key-oriented workspace methods.
/// </summary>
/// <remarks>The view holds a non-owning handle into the workspace's session; the workspace must
/// outlive it. <see cref="Dispose"/> only releases the wrapper — use <see cref="Delete"/> to
/// destroy the object on the token.</remarks>
public sealed class Pkcs11Object : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly ObjectHandle _handle;
    private readonly CKO _objectClass;
    private readonly string? _label;
    private readonly byte[] _id;
    private bool _disposed;

    internal Pkcs11Object(Pkcs11Workspace workspace, ObjectHandle handle, CKO objectClass, string? label, byte[] id)
    {
        _workspace = workspace;
        _handle = handle;
        _objectClass = objectClass;
        _label = label;
        _id = id ?? [];
    }

    /// <summary>The object's <c>CKA_CLASS</c> (e.g. <see cref="CKO.CKO_CERTIFICATE"/>, <see cref="CKO.CKO_DATA"/>).</summary>
    public CKO ObjectClass => _objectClass;

    /// <summary>The object's <c>CKA_LABEL</c>, or <c>null</c> if unset.</summary>
    public string? Label => _label;

    /// <summary>The object's <c>CKA_ID</c>. Empty if unset.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>Internal accessor for the underlying object handle.</summary>
    internal ObjectHandle Handle => _handle;

    /// <summary>
    /// Reads the object's <c>CKA_VALUE</c> — the DER-encoded certificate for a certificate
    /// object, or the payload for a data object.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><c>CKA_VALUE</c> is sensitive or unreadable.</exception>
    /// <exception cref="ObjectDisposedException">The view has been disposed.</exception>
    public byte[] GetValue()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var attrs = _workspace.Session.GetAttributeValue(_handle, [CKA.CKA_VALUE]);
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "Pkcs11Object.GetValue (CKA_VALUE unreadable)");
            return attrs[0].GetValueAsByteArray();
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <summary>
    /// Permanently removes the object from the token via <c>C_DestroyObject</c>. As with
    /// <see cref="Pkcs11Key.Delete"/>, this is distinct from <see cref="Dispose"/> and is subject
    /// to the token's <c>CKA_DESTROYABLE</c>/read-only permissions.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The view has been disposed.</exception>
    public void Delete()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _workspace.Session.DestroyObject(_handle);
    }

    /// <inheritdoc/>
    public void Dispose() => _disposed = true;
}
