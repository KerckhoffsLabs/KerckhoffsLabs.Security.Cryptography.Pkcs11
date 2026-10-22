using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// GetDSAPrivateKey is [Obsolete] (DSA is disallowed by FIPS 186-5); calling it here is deliberate.
#pragma warning disable KLPKCS11006
// The ML-DSA, ML-KEM and SLH-DSA certificate getters are evaluation-only APIs, as in the BCL (SYSLIB5006).
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <see cref="Pkcs11CertificateExtensions"/> over the managed token: a certificate stored next to a
/// key pair with the same <c>CKA_ID</c> bridges to that key as the matching BCL adapter, and every
/// mismatch — wrong algorithm, no key with that id, no id at all — yields <see langword="null"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11CertificateExtensions_Managed
{
    private const string RsaPssOid = "1.2.840.113549.1.1.10"; // id-RSASSA-PSS
    private static readonly byte[] Data = "sign via the certificate's on-token key"u8.ToArray();

    [Fact]
    public void GetRSAPrivateKey_ReturnsTheOnTokenKey_ThatSignsForTheCertificate() => WithSession(session =>
    {
        byte[] id = NewId();
        byte[] der = MintWithTokenKey(GenerateRsaKeyPair(session, id));
        StoreCertificate(session, der, id);

        using var certs = session.FindCertificates();
        using RSA? rsa = Assert.Single(certs).GetRSAPrivateKey();

        Assert.IsType<RSAPkcs11>(rsa);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var cert = X509CertificateLoader.LoadCertificate(der);
        using RSA publicKey = cert.GetRSAPublicKey()!;
        Assert.True(publicKey.VerifyData(Data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    /// <summary>The BCL treats an <c>id-RSASSA-PSS</c> SubjectPublicKeyInfo as RSA, and so must we.</summary>
    [Fact]
    public void GetRSAPrivateKey_RecognizesAnRsaPssSubjectPublicKeyInfo() => WithSession(session =>
    {
        byte[] id = NewId();
        using Pkcs11Key key = GenerateRsaKeyPair(session, id);
        byte[] der = MintRsaPssSpkiWithTokenKey(key);
        StoreCertificate(session, der, id);

        using var certs = session.FindCertificates();
        var certificate = Assert.Single(certs);
        Assert.Equal(RsaPssOid, certificate.Certificate.GetKeyAlgorithm());

        using RSA? rsa = certificate.GetRSAPrivateKey();
        Assert.IsType<RSAPkcs11>(rsa);
    });

    [Fact]
    public void GetECDsaPrivateKey_ReturnsTheOnTokenKey_ThatSignsForTheCertificate() => WithSession(session =>
    {
        byte[] id = NewId();
        byte[] der = MintWithTokenKey(GenerateEcKeyPair(session, id));
        StoreCertificate(session, der, id);

        using var certs = session.FindCertificates();
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
    public void Getters_ReturnNull_ForTheOtherAlgorithm() => WithSession(session =>
    {
        byte[] rsaId = NewId();
        StoreCertificate(session, MintWithTokenKey(GenerateRsaKeyPair(session, rsaId)), rsaId, "rsa");
        byte[] ecId = NewId();
        StoreCertificate(session, MintWithTokenKey(GenerateEcKeyPair(session, ecId)), ecId, "ec");

        using var certs = session.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetECDsaPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetRSAPrivateKey());
    });

    [Fact]
    public void Getters_ReturnNull_WhenNoKeyHasTheCertificatesId() => WithSession(session =>
    {
        StoreCertificate(session, SelfSignedRsa(), NewId(), "rsa");
        StoreCertificate(session, SelfSignedEc(), NewId(), "ec");

        using var certs = session.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetRSAPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetECDsaPrivateKey());
    });

    /// <summary>
    /// A certificate stored without <c>CKA_ID</c> has nothing to bridge by; it must not match some
    /// unrelated key, here one generated without an id either.
    /// </summary>
    [Fact]
    public void Getters_ReturnNull_WhenTheCertificateHasNoId() => WithSession(session =>
    {
        using var rsaKey = GenerateRsaKeyPair(session, id: null);
        using var ecKey = GenerateEcKeyPair(session, id: null);
        StoreCertificate(session, SelfSignedRsa(), id: null, "rsa");
        StoreCertificate(session, SelfSignedEc(), id: null, "ec");

        using var certs = session.FindCertificates();
        Assert.Null(certs.Single(c => c.Label == "rsa").GetRSAPrivateKey());
        Assert.Null(certs.Single(c => c.Label == "ec").GetECDsaPrivateKey());
    });

    [Fact]
    public void Getters_RejectANullCertificate()
    {
        Pkcs11Certificate certificate = null!;

        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetRSAPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetECDsaPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetDSAPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetECDiffieHellmanPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetMLDsaPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetMLKemPrivateKey()).ParamName);
        Assert.Equal("certificate", Assert.Throws<ArgumentNullException>(() => certificate.GetSlhDsaPrivateKey()).ParamName);
    }

    // === The other getters, shared with the real backends =================

    [Fact]
    public void GetDSAPrivateKey_SignsForTheCertificate() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_SignsForTheCertificate(session, AllMechanisms));

    [Fact]
    public void GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(session, AllMechanisms));

    [Fact]
    public void GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate(session, AllMechanisms));

    [Fact]
    public void GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(session, AllMechanisms));

    [Fact]
    public void EcGetters_FollowTheKeyUsage() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_FollowTheKeyUsage(session, AllMechanisms));

    [Fact]
    public void EcGetters_RefuseAKeyOfAnotherType() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOfAnotherType(session, AllMechanisms));

    [Fact]
    public void EcGetters_RefuseAKeyOnAnotherCurve() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOnAnotherCurve(session, AllMechanisms));

    [Fact]
    public void EcGetters_RefuseExplicitCurveParameters() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseExplicitCurveParameters(session, AllMechanisms));

    [Fact]
    public void GetMLDsaPrivateKey_SignsForTheCertificate() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_SignsForTheCertificate(session, AllMechanisms));

    [Fact]
    public void GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(session, AllMechanisms));

    [Fact]
    public void GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet(session, AllMechanisms));

    [Fact]
    public void GetMLKemPrivateKey_DecapsulatesForTheCertificate() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_DecapsulatesForTheCertificate(session, AllMechanisms));

    [Fact]
    public void GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(session, AllMechanisms));

    [Fact]
    public void GetSlhDsaPrivateKey_SignsForTheCertificate() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_SignsForTheCertificate(session, AllMechanisms));

    [Fact]
    public void GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(session => Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(session, AllMechanisms));

    // === Pairing checks no token object reaches =========================

    private static readonly PublicKey NamedP256 = NewNamedP256();

    private static PublicKey NewNamedP256()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new PublicKey(ecdsa);
    }

    [Fact]
    public void IsKeyFor_RefusesAnEcKey_WhoseCurveCannotBeRead()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));
        Assert.False(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_EC, NamedP256));
    }

    [Fact]
    public void IsKeyFor_RefusesAnEcKey_WithExplicitCurveParameters()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_OK, (byte[])[0x30, 0x00]));
        Assert.False(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_EC, NamedP256));
    }

    [Fact]
    public void IsKeyFor_RefusesAnEcCertificate_WithoutCurveParameters()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()));
        var withoutParameters = new PublicKey(NamedP256.Oid, null, NamedP256.EncodedKeyValue);

        Assert.True(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_EC, NamedP256));
        Assert.False(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_EC, withoutParameters));
    }

    private static readonly PublicKey MlDsa65 = new(new Oid("2.16.840.1.101.3.4.3.18"), null, new AsnEncodedData([0x00]));

    [Fact]
    public void IsKeyFor_RefusesAPostQuantumKey_WhoseParameterSetCannotBeRead()
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_DSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));
        Assert.False(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_ML_DSA, MlDsa65));
    }

    [Fact]
    public void IsKeyFor_RefusesAPostQuantumKey_OfAnUnknownParameterSet()
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_DSA, _ => (CKR.CKR_OK, BitConverter.GetBytes((ulong)0xFF)[..UnmanagedMemory.NativeULongSize]));
        Assert.False(Pkcs11CertificateExtensions.IsKeyFor(key, CKK.CKK_ML_DSA, MlDsa65));
    }

    // === Helpers =========================================================

    // The managed token implements every mechanism the shared cases use and advertises no list to probe;
    // the ML-DSA, ML-KEM and SLH-DSA cases still skip where the BCL lacks them.
    private static bool AllMechanisms(CKM mechanism) => true;

    private static void WithSession(Action<Pkcs11Session> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        body(session);
    }

    private static byte[] NewId() => Guid.NewGuid().ToByteArray();

    private static Pkcs11Key GenerateRsaKeyPair(Pkcs11Session session, byte[]? id)
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
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }

    private static Pkcs11Key GenerateEcKeyPair(Pkcs11Session session, byte[]? id)
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
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTemplate, privTemplate);
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

    private static void StoreCertificate(Pkcs11Session session, byte[] der, byte[]? id, string label = "cert")
    {
        using var cert = X509CertificateLoader.LoadCertificate(der);
        var builder = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Label(label).Subject(cert.SubjectName.RawData).Value(der);
        if (id is not null)
            builder = builder.Id(id);
        using var template = builder.Build();
        session.Core.CreateObject([.. template.Attributes]);
    }
}
