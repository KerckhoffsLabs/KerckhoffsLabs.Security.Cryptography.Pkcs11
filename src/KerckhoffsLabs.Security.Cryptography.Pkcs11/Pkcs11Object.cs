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
/// <remarks>
/// <para>
/// The view holds a non-owning handle into the workspace's session; the workspace must outlive it.
/// </para>
/// <para>
/// <b>Disposal never destroys token state.</b> <c>Dispose</c> releases the managed wrapper (and any
/// workspace or library this instance owns); <c>Destroy</c> is the only member that calls
/// <c>C_DestroyObject</c>. The two are kept apart deliberately: whether a handle refers to a
/// short-lived session object or to a persistent key is decided at creation by <c>CKA_TOKEN</c> —
/// a runtime template attribute, or the <c>persistOnToken</c> argument of the workspace factories —
/// so the wrapper cannot tell the two apart. Destroying when it should not is irreversible loss of
/// key material; failing to destroy a session object costs nothing, because PKCS#11 collects those
/// at <c>C_CloseSession</c>. Given that asymmetry, disposal stays inert and destruction stays
/// explicit.
/// </para>
/// </remarks>
public sealed class Pkcs11Object : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly ObjectHandle _handle;
    private readonly byte[] _id;
    private bool _disposed;

    internal Pkcs11Object(Pkcs11Workspace workspace, ObjectHandle handle, CKO objectClass, string? label, byte[] id)
    {
        _workspace = workspace;
        _handle = handle;
        ObjectClass = objectClass;
        Label = label;
        _id = id ?? [];
    }

    /// <summary>The object's <c>CKA_CLASS</c> (e.g. <see cref="CKO.CKO_CERTIFICATE"/>, <see cref="CKO.CKO_DATA"/>).</summary>
    public CKO ObjectClass { get; }

    /// <summary>The object's <c>CKA_LABEL</c>, or <c>null</c> if unset.</summary>
    public string? Label { get; }

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
        using var attrs = _workspace.Session.GetAttributeValue(_handle, [CKA.CKA_VALUE]);
        if (attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Object.GetValue (CKA_VALUE unreadable)");
        return attrs[0].GetValueAsByteArray();
    }

    /// <summary>
    /// Permanently removes the object from the token via <c>C_DestroyObject</c>. Subject to the
    /// token's <c>CKA_DESTROYABLE</c> and read-only permissions.
    /// </summary>
    /// <remarks>
    /// This is the only method that destroys anything on the token. <see cref="Dispose"/> never
    /// does — see the class remarks for why the two are kept apart.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The view has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DestroyObject</c> call.</exception>
    public void Destroy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _workspace.Session.DestroyObject(_handle);
    }

    /// <summary>
    /// Releases the managed wrapper. <b>Never destroys the token object</b> — call
    /// <see cref="Destroy"/> for that.
    /// </summary>
    /// <remarks>
    /// See the class remarks: disposal cannot know whether this handle refers to a session object
    /// the token will collect anyway or to a persistent key that must outlive the process.
    /// </remarks>
    public void Dispose() => _disposed = true;
}
