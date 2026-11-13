using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A general view over a single PKCS#11 token object — certificate, data object, or any other
/// class — returned by <see cref="Pkcs11Session.FindObjects(Objects.ObjectTemplate)"/>. Exposes
/// the object class, label/id, and the raw <c>CKA_VALUE</c> payload. For key-specific operations
/// (sign/verify/encrypt/wrap/…) use <see cref="Pkcs11Key"/> via the key-oriented session methods.
/// </summary>
/// <remarks>
/// <para>
/// The view holds a non-owning handle into the session; the session must outlive it.
/// </para>
/// <para>
/// A private object (<c>CKA_PRIVATE</c>) is tied to the token login it was found or made under: once that login
/// ends, PKCS#11 invalidates its handle for good, and <see cref="GetValue"/> and <see cref="Destroy"/> throw
/// <see cref="ObjectDisposedException"/>. Public objects are unaffected.
/// </para>
/// <para>
/// <b>Disposal never destroys token state.</b> <c>Dispose</c> releases the managed wrapper (and any
/// session or library this instance owns); <c>Destroy</c> is the only member that calls
/// <c>C_DestroyObject</c>. The two are kept apart deliberately: whether a handle refers to a
/// short-lived session object or to a persistent key is decided at creation by <c>CKA_TOKEN</c> —
/// a runtime template attribute, or the <c>persistOnToken</c> argument of the session factories —
/// so the wrapper cannot tell the two apart. Destroying when it should not is irreversible loss of
/// key material; failing to destroy a session object costs nothing, because PKCS#11 collects those
/// at <c>C_CloseSession</c>. Given that asymmetry, disposal stays inert and destruction stays
/// explicit.
/// </para>
/// </remarks>
public sealed class Pkcs11Object : IDisposable
{
    private readonly Pkcs11Session _session;
    private readonly ObjectHandle _handle;
    private readonly byte[] _id;
    private readonly LoginStamp _loginStamp;
    private bool _disposed;
    private bool _destroyed;

    internal Pkcs11Object(Pkcs11Session session, ObjectHandle handle, CKO objectClass, string? label, byte[] id,
        bool isPrivate = false, LoginStamp loginStamp = default)
    {
        _session = session;
        _handle = handle;
        ObjectClass = objectClass;
        Label = label;
        _id = id ?? [];
        IsPrivate = isPrivate;
        _loginStamp = loginStamp;
    }

    /// <summary>
    /// Whether the object is private (<c>CKA_PRIVATE</c>): usable only while the login it was found or made under lasts.
    /// </summary>
    internal bool IsPrivate { get; }

    /// <summary>The generation of the token login this object was found or made under (see <see cref="LoginStamp"/>).</summary>
    internal long LoginGeneration => _loginStamp.Generation;

    /// <summary>The object's <c>CKA_CLASS</c> (e.g. <see cref="CKO.CKO_CERTIFICATE"/>, <see cref="CKO.CKO_DATA"/>).</summary>
    public CKO ObjectClass { get; }

    /// <summary>The object's <c>CKA_LABEL</c>, or <see langword="null"/> if unset.</summary>
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
    /// <exception cref="ObjectDisposedException">The view has been disposed, or its object destroyed by <see cref="Destroy"/>, or the object is private and the login it was found or made under has ended.</exception>
    public byte[] GetValue()
    {
        using var use = Use();
        using var attrs = _session.Core.GetAttributeValue(_handle, [CKA.CKA_VALUE]);
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
    /// <para>
    /// After a successful destroy, <see cref="GetValue"/> and <c>Destroy</c> throw
    /// <see cref="ObjectDisposedException"/>: the module may give the handle to a new object, so this view
    /// must not send it again. Another view over the same object cannot learn of the destroy.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The view has been disposed, or its object already destroyed, or the object is private and the login it was found or made under has ended.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DestroyObject</c> call.</exception>
    public void Destroy()
    {
        using var use = Use();
        _session.Core.DestroyObject(_handle);
        _destroyed = true;
    }

    // The guard on every member that sends the handle: refuses a disposed view, a destroyed object, and a private
    // object whose login has ended (see PrivateObjectLogin), that last under the session's lease, which the caller
    // holds through its native calls so no logout lands in between.
    private Pkcs11SessionCore.ExclusiveLease Use([System.Runtime.CompilerServices.CallerMemberName] string? caller = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_destroyed)
            throw DestroyedObject.Exception(nameof(Pkcs11Object));

        Pkcs11SessionCore.ExclusiveLease lease = _session.Core.AcquireExclusive(caller);
        try
        {
            PrivateObjectLogin.ThrowIfEnded(IsPrivate, _loginStamp, _session.Core.LoginRecord, nameof(Pkcs11Object));
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
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
