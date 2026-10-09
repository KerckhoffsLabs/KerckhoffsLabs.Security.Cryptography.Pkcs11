using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <see cref="Pkcs11CertificateExtensions"/> over the managed token: a certificate stored next to a
/// key pair with the same <c>CKA_ID</c> bridges to that key as the matching BCL adapter, and every
/// mismatch — wrong algorithm, no key with that id, no id at all — yields <c>null</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11CertificateExtensions_Managed
{
    private const string RsaPssOid = "1.2.840.113549.1.1.10"; // id-RSASSA-PSS
    private static readonly byte[] Data = "sign via the certificate's on-token key"u8.ToArray();

    [Fact]
    public void GetRSAPrivateKey_ReturnsTheOnTokenKey_ThatSignsForTheCertificate() => WithWorkspace(workspace =>
    {
        byte[] id = NewId();
        byte[] der = MintWithTokenKey(GenerateRsaKeyPair(workspace, id));
        StoreCertificate(workspace, der, id);

        using var certs = workspace.FindCertificates();
        using RSA? rsa = Assert.Single(certs).GetRSAPrivateKey();

        Assert.IsType<RSAPkcs11>(rsa);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var cert = X509CertificateLoader.LoadCertificate(der);
        using RSA publicKey = cert.GetRSAPublicKey()!;
        Assert.True(publicKey.VerifyData(Data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    /// <summary>The BCL treats an <c>id-RSASSA-PSS</c> SubjectPublicKeyInfo as RSA, and so must we.</summary>
    [Fact]
    public void GetRSAPrivateKey_RecognizesAnRsaPssSubjectPublicKeyInfo() => WithWorkspace(workspace =>
    {
        byte[] id = NewId();
        using Pkcs11Key key = GenerateRsaKeyPair(workspace, id);
        byte[] der = MintRsaPssSpkiWithTokenKey(key);
        StoreCertificate(workspace, der, id);

        using var certs = workspace.FindCertificates();
        var certificate = Assert.Single(certs);
        Assert.Equal(RsaPssOid, certificate.Certificate.GetKeyAlgorithm());

        using RSA? rsa = certificate.GetRSAPrivateKey();
        Assert.IsType<RSAPkcs11>(rsa);
    });

    [Fact]
    public void GetECDsaPrivateKey_ReturnsTheOnTokenKey_ThatSignsForTheCertificate() => WithWorkspace(workspace =>
    {
        byte[] id = NewId();
        byte[] der = MintWithTokenKey(GenerateEcKeyPair(workspace, id));
        StoreCertificate(workspace, der, id);

        using var certs = workspace.FindCertificates();
        using ECDsa? ecdsa = Assert.Single(certs).GetECDsaPrivateKey();

        Assert.IsType<ECDsaPkcs11>(ecdsa);
        byte[] signature = ecdsa.SignData(Data, HashAlgorithmName.SHA256);
        using var cert = X509CertificateLoader.LoadCertificate(der);
        using ECDsa publicKey = cert.GetECDsaPublicKey()!;
        Assert.True(publicKey.VerifyData(Data, signature, HashAlgorithmName.SHA256));
    });

    /// <summary>
    /// Each getter answers only for its own algorithm, even when a key with the certificate's id is
    /// on the token: an RSA certificate has no ECDsa key, and the reverse.
    /// </summary>
    [Fact]
    public void Getters_ReturnNull_ForTheOtherAlgorithm() => WithWorkspace(workspace =>
    {
        byte[] rsaId = NewId();
        StoreCertificate(workspace, MintWithTokenKey(GenerateRsaKeyPair(workspace, rsaId)), rsaId, "rsa");
        byte[] ecId = NewId();
        StoreCertificate(workspace, MintWithTokenKey(GenerateEcKeyPair(workspace, ecId)), ecId, "ec");

        using var certs = workspace.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetECDsaPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetRSAPrivateKey());
    });

    [Fact]
    public void Getters_ReturnNull_WhenNoKeyHasTheCertificatesId() => WithWorkspace(workspace =>
    {
        StoreCertificate(workspace, SelfSignedRsa(), NewId(), "rsa");
        StoreCertificate(workspace, SelfSignedEc(), NewId(), "ec");

        using var certs = workspace.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetRSAPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetECDsaPrivateKey());
    });

    /// <summary>
    /// A certificate stored without <c>CKA_ID</c> has nothing to bridge by; it must not match some
    /// unrelated key, here one generated without an id either.
    /// </summary>
    [Fact]
    public void Getters_ReturnNull_WhenTheCertificateHasNoId() => WithWorkspace(workspace =>
    {
        using var rsaKey = GenerateRsaKeyPair(workspace, id: null);
        using var ecKey = GenerateEcKeyPair(workspace, id: null);
        StoreCertificate(workspace, SelfSignedRsa(), id: null, "rsa");
        StoreCertificate(workspace, SelfSignedEc(), id: null, "ec");

        using var certs = workspace.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetRSAPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetECDsaPrivateKey());
    });

    [Fact]
    public void Getters_RejectANullCertificate()
    {
        Pkcs11Certificate certificate = null!;

        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetRSAPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetECDsaPrivateKey()).ParamName);
    }

    // === Helpers =========================================================

    private static void WithWorkspace(Action<Pkcs11Workspace> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        body(workspace);
    }

    private static byte[] NewId() => Guid.NewGuid().ToByteArray();

    private static Pkcs11Key GenerateRsaKeyPair(Pkcs11Workspace workspace, byte[]? id)
    {
        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Sign();
        if (id is not null)
        {
            pub = pub.Id(id);
            priv = priv.Id(id);
        }
        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        return workspace.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }

    private static Pkcs11Key GenerateEcKeyPair(Pkcs11Workspace workspace, byte[]? id)
    {
        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Verify().EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams());
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign();
        if (id is not null)
        {
            pub = pub.Id(id);
            priv = priv.Id(id);
        }
        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        return workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }

    // Mints a certificate for the token key, signed by it through X509SignatureGenerator, so its
    // public key is the token key's and nothing tries to export the private half. Takes ownership
    // of the key handle wrapper; the key itself stays on the token.
    private static byte[] MintWithTokenKey(Pkcs11Key key)
    {
        using (key)
        {
            var subject = new X500DistinguishedName("CN=pkcs11 certificate extensions");
            CertificateRequest request;
            X509SignatureGenerator generator;
            AsymmetricAlgorithm signer;
            if (key.KeyType == CKK.CKK_RSA)
            {
                var rsa = new RSAPkcs11(key);
                signer = rsa;
                request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss);
            }
            else
            {
                var ecdsa = new ECDsaPkcs11(key);
                signer = ecdsa;
                request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
                generator = X509SignatureGenerator.CreateForECDsa(ecdsa);
            }

            using (signer)
                return Create(request, generator);
        }
    }

    // A certificate whose SubjectPublicKeyInfo carries the token key under id-RSASSA-PSS instead of
    // rsaEncryption. The parameters are an empty RSASSA-PSS-params SEQUENCE (every field at its
    // RFC 4055 default); the BCL encoder will not write them absent.
    private static byte[] MintRsaPssSpkiWithTokenKey(Pkcs11Key key)
    {
        using var rsa = new RSAPkcs11(key);
        var rsaEncryption = new CertificateRequest("CN=x", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss).PublicKey;
        var pssKey = new PublicKey(new Oid(RsaPssOid), new AsnEncodedData([0x30, 0x00]), rsaEncryption.EncodedKeyValue);

        var subject = new X500DistinguishedName("CN=pkcs11 rsa-pss spki");
        var request = new CertificateRequest(subject, pssKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Create(request, X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss));
    }

    private static byte[] Create(CertificateRequest request, X509SignatureGenerator generator)
    {
        using var cert = request.Create(request.SubjectName, generator,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), [0x01]);
        return cert.Export(X509ContentType.Cert);
    }

    private static byte[] SelfSignedRsa()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=no matching key", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.Export(X509ContentType.Cert);
    }

    private static byte[] SelfSignedEc()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=no matching key", ecdsa, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.Export(X509ContentType.Cert);
    }

    private static void StoreCertificate(Pkcs11Workspace workspace, byte[] der, byte[]? id, string label = "cert")
    {
        using var cert = X509CertificateLoader.LoadCertificate(der);
        var builder = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(label).Subject(cert.SubjectName.RawData).Value(der);
        if (id is not null)
            builder = builder.Id(id);
        using var template = builder.Build();
        workspace.Session.CreateObject([.. template.Attributes]);
    }
}
