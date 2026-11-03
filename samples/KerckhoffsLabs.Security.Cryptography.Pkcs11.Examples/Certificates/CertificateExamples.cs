using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/certificates.md: certificates on the token, and the private key behind one.</summary>
public static class CertificateExamples
{
    public static Pkcs11Certificate IssueSelfSignedCertificate(Pkcs11Session session, string label)
    {
        #region IssueSelfSignedCertificate
        // A certificate finds its private key by CKA_ID, so the key pair and the certificate share an id.
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Id(id)
            .EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams())
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Id(id)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var ecdsa = new ECDsaPkcs11(key);

        // The BCL builds the certificate; the token signs it. X509SignatureGenerator signs with the
        // ECDsa without trying to copy its private key into the certificate, which a token key refuses.
        var request = new CertificateRequest("CN=Example Signing", ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using X509Certificate2 certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForECDsa(ecdsa),
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1),
            serialNumber: RandomNumberGenerator.GetBytes(16));

        // Store it on the token next to its key. persistOnToken: true to keep it after the session.
        Pkcs11Certificate stored = session.ImportCertificate(certificate, label, id);
        #endregion
        return stored;
    }

    public static (byte[] Signature, X509Certificate2 Certificate) SignWithCertificateKey(Pkcs11Session session, string label, byte[] data)
    {
        #region SignWithCertificateKey
        // Find the certificate by label, then its private key, as X509Certificate2.GetECDsaPrivateKey()
        // would for a certificate with a software key. The returned ECDsa signs on the token.
        using Pkcs11Certificate stored = session.OpenCertificate(label);
        using ECDsa privateKey = stored.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException($"No EC signing key on the token for certificate '{label}'.");

        byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256);
        X509Certificate2 certificate = new(stored.Certificate);  // a copy that outlives the token object
        #endregion
        return (signature, certificate);
    }
}
