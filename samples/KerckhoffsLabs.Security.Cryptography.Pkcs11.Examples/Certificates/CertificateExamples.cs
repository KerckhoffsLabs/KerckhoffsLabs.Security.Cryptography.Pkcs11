using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/certificates.md: certificates on the token, and the private key behind one.</summary>
public static class CertificateExamples
{
    public static X509Certificate2 IssueSelfSignedCertificate(string modulePath, string tokenLabel, SecurePin pin, string label)
    {
        #region IssueSelfSignedCertificate
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();
        //    Refuse a label already in use: a second key under it would make OpenKey ambiguous.
        if (session.TryOpenKey(label, out Pkcs11Key? existing))
        {
            existing.Dispose();
            throw new InvalidOperationException($"A key labelled '{label}' is already on the token.");
        }

        // 2. A P-256 key pair, kept on the token (OnToken: CKA_TOKEN, so it outlives the session) under the
        //    certificate's label. A certificate finds its private key by CKA_ID, so the key pair and the
        //    certificate share an id. ForPrivateKey starts sensitive and non-extractable, with every role
        //    off: the private key may sign, the public key verify, nothing else.
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label)
            .Id(id)
            .OnToken()
            .EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams())
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label)
            .Id(id)
            .OnToken()
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var ecdsa = new ECDsaPkcs11(key);

        // 3. The BCL builds the certificate; the token signs it. X509SignatureGenerator signs with the
        //    ECDsa without trying to copy its private key into the certificate, which a token key refuses.
        //    Then store it on the token next to its key, as a token object (persistOnToken), under the
        //    label SignWithCertificateKey below opens it by. If either step fails, destroy the key pair just
        //    generated, so a retry starts from an empty label; and dispose the certificate, which is returned
        //    on success and so is not in a using.
        X509Certificate2? certificate = null;
        try
        {
            var request = new CertificateRequest("CN=Example Signing", ecdsa, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            certificate = request.Create(
                request.SubjectName,
                X509SignatureGenerator.CreateForECDsa(ecdsa),
                notBefore: DateTimeOffset.UtcNow,
                notAfter: DateTimeOffset.UtcNow.AddYears(1),
                serialNumber: RandomNumberGenerator.GetBytes(16));
            using (session.ImportCertificate(certificate, label, id, persistOnToken: true)) { }
        }
        catch
        {
            certificate?.Dispose();
            key.Destroy();
            throw;
        }
        // 4. The using declarations dispose the adapter, the key handle, the session and the library;
        //    the key pair and the certificate stay on the token.
        #endregion
        return certificate;
    }

    public static X509Certificate2 BclIssueSelfSignedCertificate()
    {
        #region BclIssueSelfSignedCertificate
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);   // the private key is in your process

        var request = new CertificateRequest("CN=Example Signing", ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        // CreateSelfSigned copies the private key into the certificate: HasPrivateKey is true.
        X509Certificate2 certificate = request.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1));
        #endregion
        return certificate;
    }

    public static Pkcs11Certificate IssueRsaPssCertificate(Pkcs11Session session, string label)
    {
        #region IssueRsaPssCertificate
        // The same steps with an RSA key: a 3072-bit pair sharing a CKA_ID with its certificate.
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Id(id)
            .ModulusBits(3072)
            .PublicExponent([0x01, 0x00, 0x01])
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Id(id)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var rsa = new RSAPkcs11(key);

        // RSASSA-PSS. Pass RSASignaturePadding.Pkcs1 to both calls instead only for a relying party that
        // does not accept PSS certificates.
        var request = new CertificateRequest("CN=Example RSA Signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using X509Certificate2 certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss),
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1),
            serialNumber: RandomNumberGenerator.GetBytes(16));

        Pkcs11Certificate stored = session.ImportCertificate(certificate, label, id);
        #endregion
        return stored;
    }

    public static Pkcs11Certificate IssueMlDsaCertificate(Pkcs11Session session, string label)
    {
        #region IssueMlDsaCertificate
        // ML-DSA-65 (FIPS 204). The certificate names the parameter set; no hash algorithm is chosen.
        // MLDsa itself is stable in .NET 10, but its CertificateRequest support is [Experimental] (SYSLIB5006).
#pragma warning disable SYSLIB5006
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Id(id)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65)
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Id(id)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var mlDsa = new MLDsaPkcs11(key);

        var request = new CertificateRequest("CN=Example ML-DSA Signing", mlDsa);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using X509Certificate2 certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForMLDsa(mlDsa),
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1),
            serialNumber: RandomNumberGenerator.GetBytes(16));

        Pkcs11Certificate stored = session.ImportCertificate(certificate, label, id);
#pragma warning restore SYSLIB5006
        #endregion
        return stored;
    }

    public static Pkcs11Certificate IssueSlhDsaCertificate(Pkcs11Session session, string label)
    {
        #region IssueSlhDsaCertificate
        // SLH-DSA-SHA2-128s (FIPS 205). SlhDsa and its adapter are [Experimental] in .NET 10 (SYSLIB5006).
#pragma warning disable SYSLIB5006
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Id(id)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Id(id)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var slhDsa = new SlhDsaPkcs11(key);

        var request = new CertificateRequest("CN=Example SLH-DSA Signing", slhDsa);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using X509Certificate2 certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForSlhDsa(slhDsa),
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1),
            serialNumber: RandomNumberGenerator.GetBytes(16));

        Pkcs11Certificate stored = session.ImportCertificate(certificate, label, id);
#pragma warning restore SYSLIB5006
        #endregion
        return stored;
    }

    public static bool VerifySelfSignatureWithBcl(X509Certificate2 certificate)
    {
        #region VerifySelfSignatureWithBcl
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }. The
        // signature covers the DER of tbsCertificate, and a self-signed certificate's own public key checks it.
        AsnReader fields = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        byte[] tbsCertificate = fields.ReadEncodedValue().ToArray();
        fields.ReadSequence();                                  // signatureAlgorithm
        byte[] signature = fields.ReadBitString(out _);

#pragma warning disable SYSLIB5006 // the ML-DSA and SLH-DSA certificate accessors are [Experimental] in .NET 10
        switch (certificate.SignatureAlgorithm.Value)
        {
            case "1.2.840.10045.4.3.2":                         // ecdsa-with-SHA256
                using (ECDsa ecdsa = certificate.GetECDsaPublicKey()!)
                    return ecdsa.VerifyData(tbsCertificate, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            case "1.2.840.113549.1.1.10":                       // RSASSA-PSS, issued above with SHA-256
                using (RSA rsa = certificate.GetRSAPublicKey()!)
                    return rsa.VerifyData(tbsCertificate, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            case "2.16.840.1.101.3.4.3.18":                     // id-ml-dsa-65
                using (MLDsa mlDsa = certificate.GetMLDsaPublicKey()!)
                    return mlDsa.VerifyData(tbsCertificate, signature);
            case "2.16.840.1.101.3.4.3.20":                     // id-slh-dsa-sha2-128s
                using (SlhDsa slhDsa = certificate.GetSlhDsaPublicKey()!)
                    return slhDsa.VerifyData(tbsCertificate, signature);
            default:
                throw new NotSupportedException($"Signature algorithm {certificate.SignatureAlgorithm.Value} is not shown here.");
        }
#pragma warning restore SYSLIB5006
        #endregion
    }

    public static (byte[] Signature, X509Certificate2 Certificate) SignWithCertificateKey(
        string modulePath, string tokenLabel, SecurePin pin, string label, byte[] data)
    {
        #region SignWithCertificateKey
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();

        // 2. Find the certificate by label, then its private key, as X509Certificate2.GetECDsaPrivateKey()
        //    would for a certificate with a software key. The returned ECDsa signs on the token.
        using Pkcs11Certificate stored = session.OpenCertificate(label);
        using ECDsa privateKey = stored.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException($"No EC signing key on the token for certificate '{label}'.");

        // 3. Sign on the token.
        byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256);
        X509Certificate2 certificate = new(stored.Certificate);  // a copy that outlives the session
        // 4. The using declarations dispose the key, the certificate handle, the session and the
        //    library, in reverse order; both objects stay on the token.
        #endregion
        return (signature, certificate);
    }

    public static byte[] BclSignWithCertificateKey(X509Certificate2 certificate, byte[] data)
    {
        #region BclSignWithCertificateKey
        // A certificate that carries its private key, from CreateSelfSigned or a PFX.
        using ECDsa privateKey = certificate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("The certificate has no EC signing key.");

        byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256);
        #endregion
        return signature;
    }
}
