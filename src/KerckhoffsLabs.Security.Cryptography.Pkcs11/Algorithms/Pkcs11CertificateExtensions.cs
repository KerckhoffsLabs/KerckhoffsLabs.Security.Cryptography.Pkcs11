using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-shaped convenience extensions over <see cref="Pkcs11Certificate"/> — mirrors
/// <c>X509Certificate2.GetRSAPrivateKey()</c> / <c>GetECDsaPrivateKey()</c> and the other private-key getters
/// by opening the matching on-token key (by <see cref="Pkcs11Certificate.Id"/>) and wrapping it as the BCL
/// adapter type.
/// </summary>
/// <remarks>
/// Each getter answers only for its own algorithm, decided by the certificate's SubjectPublicKeyInfo algorithm
/// OID and, for <c>id-ecPublicKey</c>, by its key usage extension as the BCL does. The key found by
/// <c>CKA_ID</c> must then be of that algorithm, on the certificate's named curve for EC and of its parameter
/// set for ML-DSA, ML-KEM and SLH-DSA; explicit EC curve parameters on either side are refused. A key of another kind under the same id is a mispaired token, reported as a
/// <see cref="CryptographicException"/>.
/// </remarks>
public static class Pkcs11CertificateExtensions
{
    /// <summary>
    /// Returns the certificate's on-token RSA private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="RSA"/>. Returns <see langword="null"/> when the certificate is not RSA, or
    /// no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance. Both <c>rsaEncryption</c> and <c>id-RSASSA-PSS</c> SubjectPublicKeyInfo
    /// algorithm OIDs are recognized as RSA, mirroring the BCL.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an RSA key.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    public static RSA? GetRSAPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_RSA, static key => new RSAPkcs11(key));

    /// <summary>
    /// Returns the certificate's on-token EC private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="ECDsa"/>. Returns <see langword="null"/> when the certificate is not EC,
    /// its key usage extension allows key agreement but no signature use (as the BCL decides it), or no
    /// private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns the returned
    /// instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an EC key on the certificate's named curve, or either names its curve by explicit parameters.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    public static ECDsa? GetECDsaPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_EC, static key => new ECDsaPkcs11(key), HasECDsaKeyUsage);

    /// <summary>
    /// Returns the certificate's on-token DSA private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="DSA"/>. Returns <see langword="null"/> when the certificate is not DSA, or
    /// no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not a DSA key.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    [Obsolete("DSA is disallowed for signature generation by NIST FIPS 186-5 (2023). The returned key is a DSAPkcs11, " +
              "which remains only for interop with existing DSA keys.",
        DiagnosticId = DiagnosticIds.Dsa,
        UrlFormat = DiagnosticIds.UrlFormat)]
    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Returns the DSA key the certificate is already bound to, for interop; the [Obsolete] (KLPKCS11006) warns every caller, and the token's crypto policy gates each DSA operation.")]
    public static DSA? GetDSAPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_DSA, static key => new DSAPkcs11(key));

    /// <summary>
    /// Returns the certificate's on-token EC private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="ECDiffieHellman"/>. Returns <see langword="null"/> when the certificate is
    /// not EC, its key usage extension does not allow key agreement, or no private key with this
    /// certificate's <c>CKA_ID</c> exists on the token. The caller owns the returned instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an EC key on the certificate's named curve, or either names its curve by explicit parameters.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    public static ECDiffieHellman? GetECDiffieHellmanPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_EC, static key => new ECDiffieHellmanPkcs11(key), HasECDiffieHellmanKeyUsage);

    /// <summary>
    /// Returns the certificate's on-token ML-DSA private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="MLDsa"/>. Returns <see langword="null"/> when the certificate is not
    /// ML-DSA, or no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an ML-DSA key of the certificate's parameter set.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    [Experimental("SYSLIB5006", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    public static MLDsa? GetMLDsaPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_ML_DSA, static key => new MLDsaPkcs11(key));

    /// <summary>
    /// Returns the certificate's on-token ML-KEM private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="MLKem"/>. Returns <see langword="null"/> when the certificate is not
    /// ML-KEM, or no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an ML-KEM key of the certificate's parameter set.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    [Experimental("SYSLIB5006", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    public static MLKem? GetMLKemPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_ML_KEM, static key => new MLKemPkcs11(key));

    /// <summary>
    /// Returns the certificate's on-token SLH-DSA private key (located by <see cref="Pkcs11Certificate.Id"/>)
    /// as a token-backed <see cref="SlhDsa"/>. Returns <see langword="null"/> when the certificate is not
    /// SLH-DSA, or no private key with this certificate's <c>CKA_ID</c> exists on the token. The caller owns
    /// the returned instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The private key with this certificate's <c>CKA_ID</c> is not an SLH-DSA key of the certificate's parameter set.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_FindObjects</c> lookup.</exception>
    [Experimental("SYSLIB5006", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
    public static SlhDsa? GetSlhDsaPrivateKey(this Pkcs11Certificate certificate) =>
        GetPrivateKey(certificate, CKK.CKK_SLH_DSA, static key => new SlhDsaPkcs11(key));

    // The lookup every getter shares: the certificate's algorithm (and key usage) first, as the BCL checks
    // it before touching the private key, then the key with the certificate's CKA_ID.
    private static TKey? GetPrivateKey<TKey>(
        Pkcs11Certificate certificate, CKK keyType, Func<Pkcs11Key, TKey> wrap,
        Func<X509Certificate2, bool>? hasKeyUsage = null)
        where TKey : class
    {
        ArgumentNullException.ThrowIfNull(certificate);
        string algorithm = certificate.Certificate.GetKeyAlgorithm();
        if (KeyTypeOf(algorithm) != keyType || hasKeyUsage?.Invoke(certificate.Certificate) == false) return null;

        var key = certificate.GetPrivateKey();
        if (key is null) return null;
        if (!IsKeyFor(key, keyType, certificate.Certificate.PublicKey))
        {
            key.Dispose();
            throw new CryptographicException(
                $"The private key with this certificate's CKA_ID is a {key.KeyType} key that does not match the certificate's {algorithm} public key.");
        }
        return wrap(key);
    }

    private static CKK? KeyTypeOf(string algorithm) => algorithm switch
    {
        Oids.KeyAlgorithms.RsaEncryption or Oids.KeyAlgorithms.RsaSsaPss => CKK.CKK_RSA,
        // Neither Windows nor OpenSSL permit id-ECDH as the SPKI algorithm; ECDSA and ECDH share id-ecPublicKey.
        Oids.KeyAlgorithms.EcPublicKey => CKK.CKK_EC,
        Oids.KeyAlgorithms.Dsa => CKK.CKK_DSA,
        _ => PostQuantumParameterSets.KeyTypeOf(algorithm),
    };

    // The key's type against the certificate's, and its domain: the named curve for EC, the parameter set for the
    // FIPS 203/204/205 types. Internal so the tests can reach the branches no token object produces.
    internal static bool IsKeyFor(Pkcs11Key key, CKK keyType, PublicKey publicKey)
    {
        if (key.KeyType != keyType) return false;
        if (keyType == CKK.CKK_EC)
        {
            using var ecParams = key.GetAttributeValue(CKA.CKA_EC_PARAMS);
            string? keyCurve = ecParams[0].CannotBeRead ? null : NamedCurveOid(ecParams[0].GetValueAsByteArray());
            return keyCurve is not null && keyCurve == NamedCurveOid(publicKey.EncodedParameters?.RawData ?? []);
        }
        if (keyType is not (CKK.CKK_ML_DSA or CKK.CKK_ML_KEM or CKK.CKK_SLH_DSA)) return true;

        using var parameterSet = key.GetAttributeValue(CKA.CKA_PARAMETER_SET);
        return !parameterSet[0].CannotBeRead
            && PostQuantumParameterSets.Describe(keyType, parameterSet[0].GetValueAsUlong())?.Oid == publicKey.Oid.Value;
    }

    // The namedCurve of DER-encoded EC domain parameters (RFC 5480 ECParameters), or null for explicit
    // parameters, implicitlyCA, absent parameters, or anything else that names no curve.
    private static string? NamedCurveOid(byte[] ecParameters)
    {
        try
        {
            var reader = new AsnReader(ecParameters, AsnEncodingRules.DER);
            string oid = reader.ReadObjectIdentifier();
            reader.ThrowIfNotEmpty();
            return oid;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    // As the BCL's ECDsaCertificateExtensions: without a key usage extension every use is allowed; with one,
    // a key without keyAgreement is taken as ECDSA, and one with it needs a signature use as well.
    private static bool HasECDsaKeyUsage(X509Certificate2 certificate)
    {
        if (certificate.Extensions[Oids.Extensions.KeyUsage] is not X509KeyUsageExtension ext) return true;
        const X509KeyUsageFlags ecdsaFlags =
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;
        return (ext.KeyUsages & X509KeyUsageFlags.KeyAgreement) == 0 || (ext.KeyUsages & ecdsaFlags) != 0;
    }

    // As the BCL's X509Certificate2: keyAgreement is mandatory for an id-ecPublicKey certificate used with ECDH
    // (RFC 5480 section 3); without a key usage extension every use is allowed.
    private static bool HasECDiffieHellmanKeyUsage(X509Certificate2 certificate) =>
        certificate.Extensions[Oids.Extensions.KeyUsage] is not X509KeyUsageExtension ext
        || (ext.KeyUsages & X509KeyUsageFlags.KeyAgreement) != 0;
}
