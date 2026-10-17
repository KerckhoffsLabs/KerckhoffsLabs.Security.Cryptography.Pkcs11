using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>
/// BouncyHsm counterpart of FindObjectsTests_SoftHsm: enumerate/read/delete a non-key object (an
/// X.509 certificate) via FindObjects, and bridge a stored certificate to its on-token RSA private key.
/// </summary>
[Collection("BouncyHsm")]
public sealed class FindObjectsTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void FindObjects_ReadsAndDeletes_CertificateObject()
    {
        using var session = OpenSession();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=pkcs11 find-objects test", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = cert.Export(X509ContentType.Cert);

        string label = $"octk-cert-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(label).Subject(cert.SubjectName.RawData).Value(der).OnToken().Build())
        {
            session.Core.CreateObject([.. tpl.Attributes]);
        }

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            using var objs = session.FindObjects(filter);
            var obj = Assert.Single(objs);
            Assert.Equal(CKO.CKO_CERTIFICATE, obj.ObjectClass);
            Assert.Equal(der, obj.GetValue());
        }

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var objs = session.FindObjects(filter);
            objs[0].Destroy();
            foreach (var o in objs) o.Dispose();
        }
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(session.FindObjects(filter));
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void FindCertificates_BridgesToTokenPrivateKey_AndSigns()
    {
        using var session = OpenSession();

        string baseLabel = $"octk-certkey-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(baseLabel).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).OnToken().Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(baseLabel).Id(id).Sign().OnToken().Build();
        using var keypair = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);

        byte[] der;
        byte[] subject;
        using (var signer = new RSAPkcs11(keypair))
        {
            var req = new CertificateRequest("CN=pkcs11 hsm cert", signer,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var gen = X509SignatureGenerator.CreateForRSA(signer, RSASignaturePadding.Pkcs1);
            using var minted = req.Create(req.SubjectName, gen,
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), [0x01]);
            der = minted.Export(X509ContentType.Cert);
            subject = minted.SubjectName.RawData;
        }

        string certLabel = $"{baseLabel}-cert";
        using (var certTpl = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(certLabel).Id(id).Subject(subject).Value(der).OnToken().Build())
        {
            session.Core.CreateObject([.. certTpl.Attributes]);
        }

        try
        {
            using var certs = session.FindCertificates();
            Pkcs11Certificate? cert = certs.FirstOrDefault(c => c.Label == certLabel);
            Assert.NotNull(cert);

            byte[] data = Encoding.UTF8.GetBytes("sign via FindCertificates bridge");
            using var priv = cert!.GetRSAPrivateKey();
            Assert.NotNull(priv);
            byte[] sig = priv!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var pub = cert!.Certificate.GetRSAPublicKey();
            Assert.True(pub!.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        finally
        {
            using (var cleanup = ObjectTemplate.Empty().Label(certLabel).Build())
            using (var found = session.FindObjects(cleanup))
                foreach (var o in found) o.Destroy();
            keypair.Destroy();
        }
    }
}
