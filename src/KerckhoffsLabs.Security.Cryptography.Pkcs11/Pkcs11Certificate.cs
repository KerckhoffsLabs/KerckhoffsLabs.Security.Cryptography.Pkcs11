using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A certificate object on a PKCS#11 token, returned by <see cref="Pkcs11Workspace.FindCertificates"/>.
/// Exposes the parsed <see cref="X509Certificate2"/> (identity + public key), retains the token
/// handle for <see cref="Destroy"/>, and bridges to the associated on-token private key — located by
/// the certificate's <c>CKA_ID</c> — as a <see cref="Pkcs11Key"/>.
/// </summary>
/// <remarks>
/// The certificate and its private key are two distinct token objects (PKCS#11 models them
/// separately, and a non-extractable key cannot be fused into a single <see cref="X509Certificate2"/>
/// on the OpenSSL backend). Operations on a key returned by <see cref="TryOpenPrivateKey"/> run on
/// the token and are valid only while the owning <see cref="Pkcs11Workspace"/> is open. Disposing
/// this instance disposes the wrapped <see cref="X509Certificate2"/> but does not destroy the token
/// object — use <see cref="Destroy"/>.
/// </remarks>
public sealed class Pkcs11Certificate : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly ObjectHandle _handle;
    private readonly byte[] _id;
    private readonly X509Certificate2 _certificate;
    private bool _disposed;

    internal Pkcs11Certificate(
        Pkcs11Workspace workspace, ObjectHandle handle, string? label, byte[] id, X509Certificate2 certificate)
    {
        _workspace = workspace;
        _handle = handle;
        _id = id ?? [];
        _certificate = certificate;
        Label = label;
    }

    /// <summary>The parsed X.509 certificate (identity + public key). Owned by this instance.</summary>
    public X509Certificate2 Certificate => _certificate;

    /// <summary>The object's <c>CKA_LABEL</c>, or <c>null</c> if unset.</summary>
    public string? Label { get; }

    /// <summary>The object's <c>CKA_ID</c> — also the link to the associated key objects. Empty if unset.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>Internal accessor for the underlying object handle.</summary>
    internal ObjectHandle Handle => _handle;

    /// <summary>
    /// Opens the certificate's matching on-token private key (located by <see cref="Id"/>) as a
    /// <see cref="Pkcs11Key"/>. Returns <c>null</c> when no private key with this certificate's
    /// <c>CKA_ID</c> exists on the token. The caller owns the returned key.
    /// </summary>
    /// <remarks>
    /// BCL-shaped convenience wrappers <c>GetRSAPrivateKey()</c> / <c>GetECDsaPrivateKey()</c>
    /// (mirroring <c>X509Certificate2</c>) live in the
    /// <c>KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms</c> namespace as extension methods.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The certificate has been disposed.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> call that locates the private key.</exception>
    public Pkcs11Key? TryOpenPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _workspace.TryOpenPrivateKey(_id);
    }

    /// <summary>
    /// Permanently removes the certificate object from the token via <c>C_DestroyObject</c>.
    /// The only member that destroys token state; <see cref="Dispose"/> never does. Subject to the
    /// token's <c>CKA_DESTROYABLE</c>/read-only permissions. Does not remove the associated key.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The certificate has been disposed.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_DestroyObject</c> call.</exception>
    public void Destroy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _workspace.Session.DestroyObject(_handle);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _certificate.Dispose();
        _disposed = true;
    }
}
