using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/certificates.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] CertificateCases() =>
    [
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.IssueSelfSignedCertificate)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithIssuedCertificate(b, label =>
            {
                AssertGeneratedKey(b, label, CKO.CKO_PRIVATE_KEY, CKA.CKA_SIGN);
                AssertGeneratedKey(b, label, CKO.CKO_PUBLIC_KEY, CKA.CKA_VERIFY);

                // The certificate and its key outlived the example's session: token objects, linked by CKA_ID.
                using Pkcs11Session s = b.OpenSession();
                using Pkcs11Certificate stored = s.OpenCertificate(label);
                using ECDsa? privateKey = stored.GetECDsaPrivateKey();
                Assert.NotNull(privateKey);
            }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.SignWithCertificateKey)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            // The issuing example provisions the certificate and its key on the token; this one opens them.
            b => WithIssuedCertificate(b, label =>
            {
                byte[] signature;
                X509Certificate2 certificate;
                using (SecurePin pin = UserPin(b))
                    (signature, certificate) = CertificateExamples.SignWithCertificateKey(b.LibraryPath, b.TokenLabel, pin, label, Message);
                using (certificate)
                using (ECDsa verifier = certificate.GetECDsaPublicKey()!)
                    Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256));
            }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.IssueRsaPssCertificate)), [typeof(RSAPkcs11)],
            [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                using Pkcs11Certificate stored = CertificateExamples.IssueRsaPssCertificate(s, $"example-{Guid.NewGuid():N}");
                Assert.Equal("CN=Example RSA Signing", stored.Certificate.Subject);
                Assert.Equal("1.2.840.113549.1.1.10", stored.Certificate.SignatureAlgorithm.Value); // id-RSASSA-PSS
                Assert.False(stored.Certificate.HasPrivateKey);
                Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(stored.Certificate));
                using RSA? privateKey = stored.GetRSAPrivateKey();
                Assert.NotNull(privateKey);
            })),
#pragma warning disable SYSLIB5006 // GetMLDsaPrivateKey and GetSlhDsaPrivateKey are [Experimental]; SlhDsa too, in .NET 10
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.IssueMlDsaCertificate)), [typeof(MLDsaPkcs11)],
            [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA], ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                if (!b.SupportsMlDsa) Assert.Skip("The backend cannot operate ML-DSA.");
                using Pkcs11Certificate stored = CertificateExamples.IssueMlDsaCertificate(s, $"example-{Guid.NewGuid():N}");
                Assert.Equal("CN=Example ML-DSA Signing", stored.Certificate.Subject);
                Assert.False(stored.Certificate.HasPrivateKey);
                using MLDsa? privateKey = stored.GetMLDsaPrivateKey();
                Assert.NotNull(privateKey);
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(stored.Certificate));
            })),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.IssueSlhDsaCertificate)), [typeof(SlhDsaPkcs11)],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                using Pkcs11Certificate stored = CertificateExamples.IssueSlhDsaCertificate(s, $"example-{Guid.NewGuid():N}");
                Assert.Equal("CN=Example SLH-DSA Signing", stored.Certificate.Subject);
                Assert.False(stored.Certificate.HasPrivateKey);
                using SlhDsa? privateKey = stored.GetSlhDsaPrivateKey();
                Assert.NotNull(privateKey);
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(stored.Certificate));
            })),
#pragma warning restore SYSLIB5006
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.BclIssueSelfSignedCertificate)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                using X509Certificate2 certificate = CertificateExamples.BclIssueSelfSignedCertificate();
                Assert.Equal("CN=Example Signing", certificate.Subject);
                Assert.True(certificate.HasPrivateKey);
                Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(certificate));
            }),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.BclSignWithCertificateKey)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                using X509Certificate2 certificate = CertificateExamples.BclIssueSelfSignedCertificate();
                byte[] signature = CertificateExamples.BclSignWithCertificateKey(certificate, Message);
                using ECDsa verifier = certificate.GetECDsaPublicKey()!;
                Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256));
            }),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.VerifySelfSignatureWithBcl)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                using RSA rsa = RSA.Create(3072);
                using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                foreach (CertificateRequest request in (CertificateRequest[])[
                    new("CN=BCL RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                    new("CN=BCL EC", ecdsa, HashAlgorithmName.SHA256)])
                {
                    using X509Certificate2 selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
                    Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(selfSigned), request.SubjectName.Name);
                }

                // Signed by a key other than the one it names: X509Chain with the certificate as its own custom
                // root accepts this (the trust anchor's signature is not checked); the example refuses it.
                using RSA other = RSA.Create(3072);
                var forgedRequest = new CertificateRequest("CN=Forged", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                using X509Certificate2 forged = forgedRequest.Create(forgedRequest.SubjectName,
                    X509SignatureGenerator.CreateForRSA(other, RSASignaturePadding.Pss),
                    DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), [1]);
                Assert.False(CertificateExamples.VerifySelfSignatureWithBcl(forged));
            }),
    ];

    // Runs the issuing example under a fresh label (WithGeneratedKey destroys every object with it afterwards),
    // checks the certificate it returns, then runs body with the label.
    private static void WithIssuedCertificate(IPkcs11Backend backend, Action<string> body) =>
        WithGeneratedKey(backend, label =>
        {
            using (SecurePin pin = UserPin(backend))
            using (X509Certificate2 certificate = CertificateExamples.IssueSelfSignedCertificate(backend.LibraryPath, backend.TokenLabel, pin, label))
            {
                Assert.Equal("CN=Example Signing", certificate.Subject);
                Assert.False(certificate.HasPrivateKey);
                Assert.True(CertificateExamples.VerifySelfSignatureWithBcl(certificate));
            }
            body(label);
        });
}
