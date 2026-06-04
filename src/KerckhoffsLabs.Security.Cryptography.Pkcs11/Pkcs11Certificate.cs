using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A certificate object on a PKCS#11 token, returned by <see cref="Pkcs11Workspace.FindCertificates"/>.
/// Exposes the parsed <see cref="X509Certificate2"/> (identity + public key), retains the token
/// handle for <see cref="Delete"/>, and bridges to the associated on-token private key — located by
/// the certificate's <c>CKA_ID</c> — as a <see cref="Pkcs11Key"/>.
/// </summary>
/// <remarks>
/// The certificate and its private key are two distinct token objects (PKCS#11 models them
/// separately, and a non-extractable key cannot be fused into a single <see cref="X509Certificate2"/>
/// on the OpenSSL backend). Operations on a key returned by <see cref="TryOpenPrivateKey"/> run on
/// the token and are valid only while the owning <see cref="Pkcs11Workspace"/> is open. Disposing
/// this instance disposes the wrapped <see cref="X509Certificate2"/> but does not destroy the token
/// object — use <see cref="Delete"/>.
/// </remarks>
public sealed class Pkcs11Certificate : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly ObjectHandle _handle;
    private readonly string? _label;
    private readonly byte[] _id;
    private readonly X509Certificate2 _certificate;
    private bool _disposed;

    internal Pkcs11Certificate(
        Pkcs11Workspace workspace, ObjectHandle handle, string? label, byte[] id, X509Certificate2 certificate)
    {
        _workspace = workspace;
        _handle = handle;
        _label = label;
        _id = id ?? [];
        _certificate = certificate;
    }

    /// <summary>The parsed X.509 certificate (identity + public key). Owned by this instance.</summary>
    public X509Certificate2 Certificate => _certificate;

    /// <summary>The object's <c>CKA_LABEL</c>, or <c>null</c> if unset.</summary>
    public string? Label => _label;

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
    public Pkcs11Key? TryOpenPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _workspace.TryOpenPrivateKey(_id);
    }

    /// <summary>
    /// Permanently removes the certificate object from the token via <c>C_DestroyObject</c>.
    /// Distinct from <see cref="Dispose"/> (which only releases this wrapper), and subject to the
    /// token's <c>CKA_DESTROYABLE</c>/read-only permissions. Does not remove the associated key.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The certificate has been disposed.</exception>
    public void Delete()
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
