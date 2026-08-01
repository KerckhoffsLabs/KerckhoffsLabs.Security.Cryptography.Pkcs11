using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>
/// SoftHSM-only: <see cref="Pkcs11Workspace.FindObjects"/> / <see cref="Pkcs11Object"/>
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
        var req = new CertificateRequest("CN=pkcs11 find-objects test", rsa,
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
            using var objs = workspace.FindObjects(filter);
            Assert.Single(objs);
            Assert.Equal(CKO.CKO_CERTIFICATE, objs[0].ObjectClass);
            Assert.Equal(der, objs[0].GetValue());
        }

        // Delete via the view; confirm it's gone.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var objs = workspace.FindObjects(filter);
            objs[0].Destroy();
            foreach (var o in objs) o.Dispose();
        }
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(workspace.FindObjects(filter));
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void FindCertificates_BridgesToTokenPrivateKey_AndSigns()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string baseLabel = $"certkey-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        // 1. RSA key pair on the token, sharing one CKA_ID with the cert below.
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(baseLabel).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).OnToken().Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(baseLabel).Id(id).Sign().OnToken().Build();
        using var keypair = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);

        // 2. Mint a cert SIGNED BY THE TOKEN KEY via X509SignatureGenerator (no CopyWithPrivateKey,
        //    so nothing tries to export the non-extractable key).
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

        // 3. Store the cert on the token with the SAME CKA_ID as the key.
        string certLabel = $"{baseLabel}-cert";
        using (var certTpl = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(certLabel).Id(id).Subject(subject).Value(der).OnToken().Build())
        {
            workspace.Session.CreateObject([.. certTpl.Attributes]);
        }

        try
        {
            // 4. FindCertificates -> Pkcs11Certificate; bridge to the on-token key and sign.
            using var certs = workspace.FindCertificates();
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
                foreach (var o in workspace.FindObjects(cleanup)) { o.Destroy(); o.Dispose(); }
            keypair.Destroy();
        }
    }
}
