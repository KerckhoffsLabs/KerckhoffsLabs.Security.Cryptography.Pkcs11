using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/certificates.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] CertificateCases() =>
    [
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.IssueSelfSignedCertificate)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                string label = $"example-{Guid.NewGuid():N}";
                using Pkcs11Certificate stored = CertificateExamples.IssueSelfSignedCertificate(s, label);
                Assert.Equal("CN=Example Signing", stored.Certificate.Subject);
                Assert.False(stored.Certificate.HasPrivateKey);
            }),
            Unsupported: ExampleGates.NoCertificateObjects),
        new(Name(nameof(CertificateExamples), nameof(CertificateExamples.SignWithCertificateKey)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                string label = $"example-{Guid.NewGuid():N}";
                using (CertificateExamples.IssueSelfSignedCertificate(s, label)) { }
                (byte[] signature, X509Certificate2 certificate) = CertificateExamples.SignWithCertificateKey(s, label, Message);
                using (certificate)
                using (ECDsa verifier = certificate.GetECDsaPublicKey()!)
                    Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256));
            }),
            Unsupported: ExampleGates.NoCertificateObjects),
    ];
}
