using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Objects;

/// <summary>
/// SoftHSM-only (BL-064): <see cref="Pkcs11Workspace.FindObjects"/> / <see cref="Pkcs11Object"/>
/// enumerate and read back a non-key object — an X.509 certificate — which the key-only
/// <c>FindKeys</c> path cannot reach.
/// </summary>
[Collection("SoftHsm")]
public sealed class FindObjectsTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void FindObjects_ReadsAndDeletes_CertificateObject()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        // A self-signed X.509 cert to store on the token.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=BL-064 find-objects test", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = cert.Export(X509ContentType.Cert);

        string label = $"cert-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(label)
            .Subject(cert.SubjectName.RawData)
            .Value(der)
            .OnToken()
            .Build())
        {
            workspace.Session.CreateObject([.. tpl.Attributes]);
        }

        // FindObjects sees the certificate and reads it back.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var objs = workspace.FindObjects(filter);
            try
            {
                Assert.Single(objs);
                Assert.Equal(CKO.CKO_CERTIFICATE, objs[0].ObjectClass);
                Assert.Equal(der, objs[0].GetValue());
                using var roundTrip = objs[0].AsX509Certificate();
                Assert.Equal(cert.Thumbprint, roundTrip.Thumbprint);
            }
            finally
            {
                foreach (var o in objs) o.Dispose();
            }
        }

        // FindCertificates() convenience returns the cert among CKO_CERTIFICATE objects.
        {
            var certs = workspace.FindCertificates();
            try
            {
                Assert.Contains(certs, o => o.Label == label && o.ObjectClass == CKO.CKO_CERTIFICATE);
            }
            finally
            {
                foreach (var o in certs) o.Dispose();
            }
        }

        // Delete via the view; confirm it's gone.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var objs = workspace.FindObjects(filter);
            objs[0].Delete();
            foreach (var o in objs) o.Dispose();
        }
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(workspace.FindObjects(filter));
    }
}
