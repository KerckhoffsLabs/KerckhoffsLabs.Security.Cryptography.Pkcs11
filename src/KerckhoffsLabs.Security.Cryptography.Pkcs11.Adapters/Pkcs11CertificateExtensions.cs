using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// BCL-shaped convenience extensions over <see cref="Pkcs11Certificate"/> — mirrors
/// <c>X509Certificate2.GetRSAPrivateKey()</c> / <c>GetECDsaPrivateKey()</c> by opening the matching
/// on-token key (by <see cref="Pkcs11Certificate.Id"/>) and wrapping it as the BCL adapter type.
/// </summary>
public static class Pkcs11CertificateExtensions
{
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcOid = "1.2.840.10045.2.1";

    /// <summary>
    /// Returns the certificate's on-token RSA private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="RSA"/>. Returns <c>null</c> when the certificate is not RSA, or
    /// no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    public static RSA? GetRSAPrivateKey(this Pkcs11Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (certificate.Certificate.GetKeyAlgorithm() != RsaOid) return null;
        var key = certificate.TryOpenPrivateKey();
        return key is null ? null : new RSAPkcs11(key);
    }

    /// <summary>
    /// Returns the certificate's on-token EC private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="ECDsa"/>. Returns <c>null</c> when the certificate is not EC,
    /// or no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    public static ECDsa? GetECDsaPrivateKey(this Pkcs11Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (certificate.Certificate.GetKeyAlgorithm() != EcOid) return null;
        var key = certificate.TryOpenPrivateKey();
        return key is null ? null : new ECDsaPkcs11(key);
    }
}
