using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A certificate object on a PKCS#11 token, returned by <see cref="Pkcs11Workspace.FindCertificates"/>.
/// Exposes the parsed <see cref="X509Certificate2"/> (identity + public key), retains the token
/// handle for <see cref="Delete"/>, and bridges to the associated on-token private key — located by
/// the certificate's <c>CKA_ID</c> — as a BCL <see cref="RSA"/> / <see cref="ECDsa"/>.
/// </summary>
/// <remarks>
/// The certificate and its private key are two distinct token objects (PKCS#11 models them
/// separately, and a non-extractable key cannot be fused into a single <see cref="X509Certificate2"/>
/// on the OpenSSL backend). Operations on a key returned by <see cref="GetRSAPrivateKey"/> /
/// <see cref="GetECDsaPrivateKey"/> run on the token and are valid only while the owning
/// <see cref="Pkcs11Workspace"/> is open. Disposing this instance disposes the wrapped
/// <see cref="X509Certificate2"/> but does not destroy the token object — use <see cref="Delete"/>.
/// </remarks>
public sealed class Pkcs11Certificate : IDisposable
{
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcOid = "1.2.840.10045.2.1";

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
    /// Returns the certificate's on-token RSA private key (located by <see cref="Id"/>) as a
    /// token-backed <see cref="RSA"/>, mirroring <c>X509Certificate2.GetRSAPrivateKey()</c>.
    /// Returns <c>null</c> when the certificate is not RSA, or no private key with this
    /// certificate's <c>CKA_ID</c> exists on the token. The caller owns the returned instance.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The certificate has been disposed.</exception>
    public RSA? GetRSAPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_certificate.GetKeyAlgorithm() != RsaOid) return null;
        var key = _workspace.TryOpenPrivateKey(_id);
        return key is null ? null : new RSAPkcs11(key);
    }

    /// <summary>
    /// Returns the certificate's on-token EC private key (located by <see cref="Id"/>) as a
    /// token-backed <see cref="ECDsa"/>, mirroring <c>X509Certificate2.GetECDsaPrivateKey()</c>.
    /// Returns <c>null</c> when the certificate is not EC, or no private key with this
    /// certificate's <c>CKA_ID</c> exists on the token. The caller owns the returned instance.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The certificate has been disposed.</exception>
    public ECDsa? GetECDsaPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_certificate.GetKeyAlgorithm() != EcOid) return null;
        var key = _workspace.TryOpenPrivateKey(_id);
        return key is null ? null : new ECDsaPkcs11(key);
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
