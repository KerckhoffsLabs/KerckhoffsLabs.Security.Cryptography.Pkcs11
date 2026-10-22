using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

// GetDSAPrivateKey is [Obsolete] (DSA is disallowed by FIPS 186-5); calling it here is deliberate.
#pragma warning disable KLPKCS11006
// The ML-DSA, ML-KEM and SLH-DSA certificate getters are evaluation-only APIs, as in the BCL (SYSLIB5006).
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic <see cref="Pkcs11CertificateExtensions"/> cases for the DSA, ECDH, ML-DSA, ML-KEM and
/// SLH-DSA getters. Each stores a certificate for a key on the token under the key's <c>CKA_ID</c>, issued
/// by a throwaway BCL CA so any key type can be certified, and checks that the getter's adapter works
/// against the certificate's public key, that no other getter answers for that certificate, and that a
/// certificate without a key on the token yields <see langword="null"/>. Cases skip where the backend does
/// not advertise the mechanisms, or where the BCL cannot check the result (ML-DSA, ML-KEM, SLH-DSA need OS
/// support).
/// </summary>
internal static class Pkcs11CertificateExtensionsTestCases
{
    private static readonly byte[] Data = "sign via the certificate's on-token key"u8.ToArray();

    // FIPS 186-2 sized (160-bit Q): Windows decodes a certificate's DSA public key through a CAPI DSS blob,
    // which holds at most a 20-byte Q, so a 2048-bit key's certificate has no BCL public key there.
    private const int DsaKeySize = 1024;

    // macOS's BCL cannot generate a DSA key of any size (and hashes DSA data with SHA-1 only).
    private static readonly bool BclDsaSupported = ProbeDsa();

    private static bool ProbeDsa()
    {
        try
        {
            using var dsa = DSA.Create(DsaKeySize);
            dsa.ExportParameters(includePrivateParameters: false);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // Every getter by the name of its algorithm, to check that only the expected ones answer.
    private static readonly (string Name, Func<Pkcs11Certificate, IDisposable?> Get)[] Getters =
    [
        ("RSA", c => c.GetRSAPrivateKey()),
        ("ECDsa", c => c.GetECDsaPrivateKey()),
        ("DSA", c => c.GetDSAPrivateKey()),
        ("ECDiffieHellman", c => c.GetECDiffieHellmanPrivateKey()),
        ("MLDsa", c => c.GetMLDsaPrivateKey()),
        ("MLKem", c => c.GetMLKemPrivateKey()),
        ("SlhDsa", c => c.GetSlhDsaPrivateKey()),
    ];

    // === DSA ======================================================================================

    internal static void Assert_GetDSAPrivateKey_SignsForTheCertificate(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireDsa(supports);
        byte[] id = NewId();
        using var key = ImportDsaKeyPair(session, id);
        using var certificate = Store(session, IssueFor(key), id);

        AssertOnlyTheseAnswer(certificate, "DSA");
        // Every CKM_DSA* operation is gated as FIPS 186-5-disallowed.
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using DSA? dsa = certificate.GetDSAPrivateKey();
        Assert.IsType<DSAPkcs11>(dsa);
        byte[] signature = dsa.SignData(Data, HashAlgorithmName.SHA256);
        // Windows decodes a certificate's DSA key as a DSACryptoServiceProvider, which hashes with SHA-1 only;
        // a DSA made from its parameters (CNG there) verifies SHA-256, truncated to Q as FIPS 186-3 does.
        using DSA certificateKey = certificate.Certificate.GetDSAPublicKey()!;
        using DSA publicKey = DSA.Create(certificateKey.ExportParameters(includePrivateParameters: false));
        Assert.True(publicKey.VerifyData(Data, signature, HashAlgorithmName.SHA256));
    }

    internal static void Assert_GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireDsa(supports);
        using var dsa = DSA.Create(DsaKeySize);
        using var certificate = Store(session, IssueFor(new PublicKey(dsa)), NewId());

        Assert.Null(certificate.GetDSAPrivateKey());
    }

    // === ECDH =====================================================================================

    internal static void Assert_GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        byte[] id = NewId();
        using var key = GenerateEcKeyPair(session, id);
        using var certificate = Store(session, IssueFor(key, X509KeyUsageFlags.KeyAgreement), id);

        AssertOnlyTheseAnswer(certificate, "ECDiffieHellman");
        // Every ECDiffieHellman derivation reads the agreement off the token, which the default policy refuses.
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using ECDiffieHellman? ecdh = certificate.GetECDiffieHellmanPrivateKey();
        Assert.IsType<ECDiffieHellmanPkcs11>(ecdh);
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDiffieHellman publicKey = certificate.Certificate.GetECDiffieHellmanPublicKey()!;
        Assert.Equal(
            peer.DeriveKeyFromHash(publicKey.PublicKey, HashAlgorithmName.SHA256),
            ecdh.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256));
    }

    internal static void Assert_GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = Store(session, IssueFor(new PublicKey(ecdh)), NewId());

        Assert.Null(certificate.GetECDiffieHellmanPrivateKey());
    }

    /// <summary>
    /// ECDSA and ECDH share <c>id-ecPublicKey</c>; as in the BCL, the key usage extension decides which of the
    /// two getters answers, and a certificate without one answers both.
    /// </summary>
    internal static void Assert_EcGetters_FollowTheKeyUsage(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        byte[] id = NewId();
        using var key = GenerateEcKeyPair(session, id);

        AssertOnlyTheseAnswerFor(session, id, IssueFor(key), "ECDsa", "ECDiffieHellman");
        AssertOnlyTheseAnswerFor(session, id, IssueFor(key, X509KeyUsageFlags.DigitalSignature), "ECDsa");
        AssertOnlyTheseAnswerFor(session, id, IssueFor(key, X509KeyUsageFlags.KeyAgreement), "ECDiffieHellman");
        AssertOnlyTheseAnswerFor(session, id,
            IssueFor(key, X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.KeyCertSign), "ECDsa", "ECDiffieHellman");
        AssertOnlyTheseAnswerFor(session, id, IssueFor(key, X509KeyUsageFlags.KeyEncipherment), "ECDsa");
    }

    /// <summary>
    /// A key of another type under the certificate's <c>CKA_ID</c> is a mispaired token, not a missing key:
    /// it throws <see cref="CryptographicException"/> instead of wrapping a key that cannot match.
    /// </summary>
    internal static void Assert_EcGetters_RefuseAKeyOfAnotherType(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        if (!supports(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN))
            Assert.Skip("Backend does not advertise CKM_RSA_PKCS_KEY_PAIR_GEN.");
        byte[] id = NewId();
        using var rsaKey = GenerateRsaKeyPair(session, id);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = Store(session, IssueFor(new PublicKey(ecdsa)), id);

        Assert.Throws<CryptographicException>(() => certificate.GetECDsaPrivateKey());
        Assert.Throws<CryptographicException>(() => certificate.GetECDiffieHellmanPrivateKey());
    }

    /// <summary>
    /// An EC key on another curve than the certificate's under its <c>CKA_ID</c> is mispaired as well.
    /// </summary>
    internal static void Assert_EcGetters_RefuseAKeyOnAnotherCurve(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        byte[] id = NewId();
        using var p384Key = GenerateEcKeyPair(session, id, Pkcs11ECCurve.NamedCurves.NistP384);
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = Store(session, IssueFor(new PublicKey(p256)), id);

        Assert.Throws<CryptographicException>(() => certificate.GetECDsaPrivateKey());
        Assert.Throws<CryptographicException>(() => certificate.GetECDiffieHellmanPrivateKey());
    }

    /// <summary>
    /// A certificate that spells its curve out as explicit parameters names no curve to match the key's
    /// against, so even a key on the same curve is refused rather than assumed to match.
    /// </summary>
    internal static void Assert_EcGetters_RefuseExplicitCurveParameters(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequireEcdh(supports);
        byte[] id = NewId();
        using var key = GenerateEcKeyPair(session, id);
        using var certificate = Store(session, IssueFor(ExplicitP256PublicKey()), id);

        Assert.Throws<CryptographicException>(() => certificate.GetECDsaPrivateKey());
        Assert.Throws<CryptographicException>(() => certificate.GetECDiffieHellmanPrivateKey());
    }

    // === ML-DSA ===================================================================================

    internal static void Assert_GetMLDsaPrivateKey_SignsForTheCertificate(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, MLDsa.IsSupported, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        byte[] id = NewId();
        using var key = GenerateMlDsaKeyPair(session, id, CkpMlDsa.CKP_ML_DSA_65);
        using var certificate = Store(session, IssueFor(key), id);

        AssertOnlyTheseAnswer(certificate, "MLDsa");
        using MLDsa? mldsa = certificate.GetMLDsaPrivateKey();
        Assert.IsType<MLDsaPkcs11>(mldsa);
        Assert.Equal(MLDsaAlgorithm.MLDsa65, mldsa.Algorithm);
        byte[] signature = mldsa.SignData(Data);
        using MLDsa publicKey = certificate.Certificate.GetMLDsaPublicKey()!;
        Assert.True(publicKey.VerifyData(Data, signature));
    }

    internal static void Assert_GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, MLDsa.IsSupported, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        using var mldsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var certificate = Store(session, IssueFor(PublicKeyOf(mldsa.ExportSubjectPublicKeyInfo())), NewId());

        Assert.Null(certificate.GetMLDsaPrivateKey());
    }

    /// <summary>
    /// The certificate's OID names the parameter set; an ML-DSA key of another one under its <c>CKA_ID</c>
    /// cannot be its private key.
    /// </summary>
    internal static void Assert_GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, MLDsa.IsSupported, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        byte[] id = NewId();
        using var key = GenerateMlDsaKeyPair(session, id, CkpMlDsa.CKP_ML_DSA_44);
        using var mldsa65 = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var certificate = Store(session, IssueFor(PublicKeyOf(mldsa65.ExportSubjectPublicKeyInfo())), id);

        Assert.Throws<CryptographicException>(() => certificate.GetMLDsaPrivateKey());
    }

    // === ML-KEM ===================================================================================

    internal static void Assert_GetMLKemPrivateKey_DecapsulatesForTheCertificate(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, MLKem.IsSupported, CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM);
        byte[] id = NewId();
        using var key = GenerateMlKemKeyPair(session, id, CkpMlKem.CKP_ML_KEM_768);
        using var certificate = Store(session, IssueFor(key), id);

        AssertOnlyTheseAnswer(certificate, "MLKem");
        // Decapsulation hands the shared secret back to the caller, which the default policy refuses.
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using MLKem? mlkem = certificate.GetMLKemPrivateKey();
        Assert.IsType<MLKemPkcs11>(mlkem);
        using MLKem publicKey = certificate.Certificate.GetMLKemPublicKey()!;
        publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        Assert.Equal(sharedSecret, mlkem.Decapsulate(ciphertext));
    }

    internal static void Assert_GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, MLKem.IsSupported, CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM);
        using var mlkem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        using var certificate = Store(session, IssueFor(PublicKeyOf(mlkem.ExportSubjectPublicKeyInfo())), NewId());

        Assert.Null(certificate.GetMLKemPrivateKey());
    }

    // === SLH-DSA ==================================================================================

    internal static void Assert_GetSlhDsaPrivateKey_SignsForTheCertificate(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, SlhDsa.IsSupported, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA);
        byte[] id = NewId();
        using var key = GenerateSlhDsaKeyPair(session, id, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F);
        using var certificate = Store(session, IssueFor(key), id);

        AssertOnlyTheseAnswer(certificate, "SlhDsa");
        using SlhDsa? slhdsa = certificate.GetSlhDsaPrivateKey();
        Assert.IsType<SlhDsaPkcs11>(slhdsa);
        byte[] signature = slhdsa.SignData(Data);
        using SlhDsa publicKey = certificate.Certificate.GetSlhDsaPublicKey()!;
        Assert.True(publicKey.VerifyData(Data, signature));
    }

    internal static void Assert_GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken(Pkcs11Session session, Func<CKM, bool> supports)
    {
        RequirePostQuantum(supports, SlhDsa.IsSupported, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA);
        using var slhdsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128f);
        using var certificate = Store(session, IssueFor(PublicKeyOf(slhdsa.ExportSubjectPublicKeyInfo())), NewId());

        Assert.Null(certificate.GetSlhDsaPrivateKey());
    }

    // === Helpers ==================================================================================

    private static void RequireDsa(Func<CKM, bool> supports)
    {
        if (!BclDsaSupported)
            Assert.Skip("The BCL cannot make a DSA key here (macOS cannot generate one).");
        if (!supports(CKM.CKM_DSA))
            Assert.Skip("Backend does not advertise CKM_DSA.");
    }

    private static void RequireEcdh(Func<CKM, bool> supports)
    {
        if (!supports(CKM.CKM_EC_KEY_PAIR_GEN) || !supports(CKM.CKM_ECDH1_DERIVE))
            Assert.Skip("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDH1_DERIVE.");
    }

    private static void RequirePostQuantum(Func<CKM, bool> supports, bool bclSupported, CKM generate, CKM operate)
    {
        if (!bclSupported)
            Assert.Skip("The BCL cannot check the result here (needs OS post-quantum support).");
        if (!supports(generate) || !supports(operate))
            Assert.Skip($"Backend does not advertise {generate} + {operate}.");
    }

    private static byte[] NewId() => Guid.NewGuid().ToByteArray();

    private static void AssertOnlyTheseAnswer(Pkcs11Certificate certificate, params string[] expected)
    {
        var answering = new List<string>();
        foreach (var (name, get) in Getters)
        {
            using var key = get(certificate);
            if (key is not null) answering.Add(name);
        }
        Assert.Equal(expected, answering);
    }

    private static void AssertOnlyTheseAnswerFor(Pkcs11Session session, byte[] id, X509Certificate2 issued, params string[] expected)
    {
        using var certificate = Store(session, issued, id);
        AssertOnlyTheseAnswer(certificate, expected);
        certificate.Destroy();
    }

    // Stores the certificate as a session object under the key's CKA_ID, and disposes the issued copy.
    private static Pkcs11Certificate Store(Pkcs11Session session, X509Certificate2 issued, byte[] id)
    {
        using (issued)
            return session.ImportCertificate(issued, "pkcs11 certificate extensions", id);
    }

    private static X509Certificate2 IssueFor(Pkcs11Key key, X509KeyUsageFlags? keyUsage = null) =>
        IssueFor(PublicKeyOf(key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo)), keyUsage);

    // A P-256 public key whose SubjectPublicKeyInfo spells the curve out as SpecifiedECDomain (SEC 1 C.2) instead
    // of naming it. Written by hand: macOS's BCL exports and imports named curves only.
    private static PublicKey ExplicitP256PublicKey()
    {
        using var named = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters q = named.ExportParameters(includePrivateParameters: false);

        var parameters = new AsnWriter(AsnEncodingRules.DER);
        using (parameters.PushSequence())
        {
            parameters.WriteInteger(1);
            using (parameters.PushSequence())
            {
                parameters.WriteObjectIdentifier("1.2.840.10045.1.1"); // prime-field (X9.62)
                parameters.WriteIntegerUnsigned(P256.P);
            }
            using (parameters.PushSequence())
            {
                parameters.WriteOctetString(P256.A);
                parameters.WriteOctetString(P256.B);
            }
            parameters.WriteOctetString([0x04, .. P256.Gx, .. P256.Gy]);
            parameters.WriteIntegerUnsigned(P256.N);
            parameters.WriteInteger(1);
        }
        byte[] encoded = parameters.Encode();
        Assert.Equal(0x30, encoded[0]); // a SEQUENCE (SpecifiedECDomain), not an OID

        return new PublicKey(
            new Oid("1.2.840.10045.2.1"), // id-ecPublicKey
            new AsnEncodedData(encoded),
            new AsnEncodedData([0x04, .. q.Q.X!, .. q.Q.Y!]));
    }

    // NIST P-256 domain parameters (FIPS 186-4 D.1.2.3, SEC 2 2.4.2).
    private static class P256
    {
        internal static readonly byte[] P = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        internal static readonly byte[] A = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
        internal static readonly byte[] B = Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
        internal static readonly byte[] Gx = Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        internal static readonly byte[] Gy = Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        internal static readonly byte[] N = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    }

    private static PublicKey PublicKeyOf(byte[] subjectPublicKeyInfo) =>
        PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);

    // A certificate for any public key, issued by a throwaway BCL ECDSA CA: neither the key's algorithm nor
    // its private half on the token has to be able to sign it.
    private static X509Certificate2 IssueFor(PublicKey publicKey, X509KeyUsageFlags? keyUsage = null)
    {
        using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=pkcs11 certificate extensions"), publicKey, HashAlgorithmName.SHA256);
        if (keyUsage is { } usage)
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, critical: true));
        return request.Create(
            new X500DistinguishedName("CN=pkcs11 certificate extensions CA"), X509SignatureGenerator.CreateForECDsa(issuer),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), [0x01]);
    }

    // The managed token cannot generate a DSA key inside given domain parameters, so a BCL key is imported
    // on every backend: the public half first, then the private half, which finds it by CKA_ID.
    private static Pkcs11Key ImportDsaKeyPair(Pkcs11Session session, byte[] id)
    {
        using var bcl = DSA.Create(DsaKeySize);
        DSAParameters full = bcl.ExportParameters(includePrivateParameters: true);
        try
        {
            using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
                .Id(id).Verify()
                .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
                .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.Y!).Build();
            using (session.ImportKey(pubTpl)) { }

            using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
                .Id(id).Sign()
                .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
                .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.X!).Build();
            return session.ImportKey(privTpl);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(full.X);
        }
    }

    // Sign and derive on one key, so both EC getters have something to wrap.
    private static Pkcs11Key GenerateEcKeyPair(Pkcs11Session session, byte[] id, Pkcs11ECCurve? curve = null)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Id(id).Verify().EcParams((curve ?? Pkcs11ECCurve.NamedCurves.NistP256).GetEcParams()).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Id(id).Sign().Derive().Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static Pkcs11Key GenerateRsaKeyPair(Pkcs11Session session, byte[] id)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Id(id).Sign().Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static Pkcs11Key GenerateMlDsaKeyPair(Pkcs11Session session, byte[] id, CkpMlDsa parameterSet)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Id(id).Verify().Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA).Id(id).Sign().Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static Pkcs11Key GenerateMlKemKeyPair(Pkcs11Session session, byte[] id, CkpMlKem parameterSet)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Id(id).Attribute(CKA.CKA_ENCAPSULATE, true).Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Id(id).Attribute(CKA.CKA_DECAPSULATE, true).Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static Pkcs11Key GenerateSlhDsaKeyPair(Pkcs11Session session, byte[] id, CkpSlhDsa parameterSet)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Id(id).Verify().Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA).Id(id).Sign().Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
    }
}
