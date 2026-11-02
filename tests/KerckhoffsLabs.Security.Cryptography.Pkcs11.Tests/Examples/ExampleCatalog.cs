using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>The CI backends an example can be required to run on.</summary>
[Flags]
internal enum ExampleBackend
{
    SoftHsm2 = 1,
    Kryoptic = 2,
    Nss = 4,
    BouncyHsm = 8,
    WolfPkcs11 = 16,
}

/// <summary>One documentation example, as the tests run it.</summary>
/// <param name="Name"><c>"&lt;Class&gt;.&lt;Method&gt;"</c> of the example in the examples project.</param>
/// <param name="Covers">The adapter types the example documents.</param>
/// <param name="Requires">The mechanisms the backend must advertise for the example to run.</param>
/// <param name="MustRunOn">The backends on which a skip is a failure on the full-backend CI leg.</param>
/// <param name="Run">Calls the example and asserts its outcome.</param>
/// <param name="NeedsUserLogin">The example logs in with the user PIN itself, so it cannot run on a
/// token that refuses <c>C_Login</c> (NSS's login-less crypto token).</param>
/// <param name="Unsupported">Why this backend cannot run the example although it advertises the
/// mechanisms (a known capability gap of that module or version), or <see langword="null"/> when it can.
/// Judged by the same skip-or-fail rule as <paramref name="Requires"/>.</param>
internal sealed record ExampleCase(
    string Name,
    Type[] Covers,
    CKM[] Requires,
    ExampleBackend MustRunOn,
    Action<IPkcs11Backend> Run,
    bool NeedsUserLogin = false,
    Func<IPkcs11Backend, string?>? Unsupported = null);

/// <summary>Known capability gaps the catalogue's <see cref="ExampleCase.Unsupported"/> gates reuse.</summary>
internal static class ExampleGates
{
    /// <summary>NSS before 3.52 cannot run classic AES-GCM (see <see cref="NssBackendFixture.RequireClassicAesGcm"/>).</summary>
    public static string? ClassicAesGcm(IPkcs11Backend backend) =>
        backend is NssBackendFixture nss && !nss.Library.LowLevelLibrary!.IsBoundThroughV3Interface
            ? "NSS before 3.52 reads CK_GCM_PARAMS without ulIvBits, so classic AES-GCM fails on it"
            : null;
}

/// <summary>Every documentation example, with the assertions that prove it does what its page says.</summary>
internal static class ExampleCatalog
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("Pay 100 EUR to account 42.");
    private static readonly byte[] Header = Encoding.UTF8.GetBytes("message-id: 7");

    public static IReadOnlyList<ExampleCase> All { get; } =
    [
        new(
            $"{nameof(GettingStartedExamples)}.{nameof(GettingStartedExamples.ReadPinFromEnvironment)}",
            [],
            [],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertReadPinFromEnvironment,
            NeedsUserLogin: true),
        new(
            $"{nameof(GettingStartedExamples)}.{nameof(GettingStartedExamples.EncryptAndDecryptWithTokenKey)}",
            [],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertEncryptAndDecryptWithTokenKey,
            NeedsUserLogin: true,
            Unsupported: ExampleGates.ClassicAesGcm),

        // AEAD (docs/examples/aead.md)
        new(Name(nameof(AeadExamples.AesGcmEncryptDecrypt)), [typeof(AesGcmPkcs11)], [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(Message, AeadExamples.AesGcmEncryptDecrypt(s, Message, Header))),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Name(nameof(AeadExamples.BclAesGcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, AeadExamples.BclAesGcmEncryptDecrypt(Message, Header))),
        new(Name(nameof(AeadExamples.AesGcmDetectsTampering)), [typeof(AesGcmPkcs11)], [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.True(AeadExamples.AesGcmDetectsTampering(s, Message))),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Name(nameof(AeadExamples.AesCcmEncryptDecrypt)), [typeof(AesCcmPkcs11)], [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CCM],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(Message, AeadExamples.AesCcmEncryptDecrypt(s, Message, Header)))),
        new(Name(nameof(AeadExamples.BclAesCcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!AesCcm.IsSupported) Assert.Skip("AES-CCM is not supported on this platform.");
                Assert.Equal(Message, AeadExamples.BclAesCcmEncryptDecrypt(Message, Header));
            }),
        new(Name(nameof(AeadExamples.ChaCha20Poly1305EncryptDecrypt)), [typeof(ChaCha20Poly1305Pkcs11)],
            [CKM.CKM_CHACHA20_KEY_GEN, CKM.CKM_CHACHA20_POLY1305],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(Message, AeadExamples.ChaCha20Poly1305EncryptDecrypt(s, Message, Header)))),
        new(Name(nameof(AeadExamples.BclChaCha20Poly1305EncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!ChaCha20Poly1305.IsSupported) Assert.Skip("ChaCha20-Poly1305 is not supported on this platform.");
                Assert.Equal(Message, AeadExamples.BclChaCha20Poly1305EncryptDecrypt(Message, Header));
            }),

        // AES block modes (docs/examples/aes.md)
        new($"{nameof(AesModeExamples)}.{nameof(AesModeExamples.CbcPadUnderReviewedPolicy)}", [typeof(AesPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CBC_PAD], ExampleBackend.SoftHsm2,
            AssertCbcPadUnderReviewedPolicy, NeedsUserLogin: true),
        new($"{nameof(AesModeExamples)}.{nameof(AesModeExamples.BclCbcPad)}", [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, AesModeExamples.BclCbcPad(Message))),

        // RSA (docs/examples/rsa.md)
        new(Rsa(nameof(RsaExamples.SignPss)), [typeof(RSAPkcs11)], [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (byte[] signature, RSAParameters publicKey) = RsaExamples.SignPss(s, Message);
                Assert.True(RsaExamples.VerifyPssWithBcl(Message, signature, publicKey));
                Assert.False(RsaExamples.VerifyPssWithBcl([.. Message, 0], signature, publicKey));
            })),
        new(Rsa(nameof(RsaExamples.VerifyPssWithBcl)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                using RSA bcl = RSA.Create(3072);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                Assert.True(RsaExamples.VerifyPssWithBcl(Message, signature, bcl.ExportParameters(false)));
            }),
        new(Rsa(nameof(RsaExamples.SignPkcs1v15)), [typeof(RSAPkcs11)], [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (byte[] signature, RSAParameters publicKey) = RsaExamples.SignPkcs1v15(s, Message);
                using RSA bcl = RSA.Create(publicKey);
                Assert.True(bcl.VerifyData(Message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            })),
        new(Rsa(nameof(RsaExamples.OaepEncryptDecrypt)), [typeof(RSAPkcs11)], [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(Message, RsaExamples.OaepEncryptDecrypt(s, Message))),
            Unsupported: b => b is SoftHsmBackendFixture && SoftHsmBackendFixture.IsV240Leg
                ? "SoftHSM 2.5 implements RSA-OAEP with SHA-1 only"
                : null),
        new(Rsa(nameof(RsaExamples.BclOaepEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, RsaExamples.BclOaepEncryptDecrypt(Message))),

        // Elliptic curves (docs/examples/elliptic-curves.md)
        new($"{nameof(EcExamples)}.{nameof(EcExamples.SignP256)}", [typeof(ECDsaPkcs11)], [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (byte[] signature, ECParameters publicKey) = EcExamples.SignP256(s, Message);
                Assert.True(EcExamples.VerifyWithBcl(Message, signature, publicKey));
                Assert.False(EcExamples.VerifyWithBcl([.. Message, 0], signature, publicKey));
            })),
        new($"{nameof(EcExamples)}.{nameof(EcExamples.VerifyWithBcl)}", [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                using ECDsa bcl = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256);
                Assert.True(EcExamples.VerifyWithBcl(Message, signature, bcl.ExportParameters(false)));
            }),
        new($"{nameof(EcExamples)}.{nameof(EcExamples.AgreeAesKeyWithBclPeer)}", [typeof(ECDiffieHellmanPkcs11)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE, CKM.CKM_HKDF_DERIVE, CKM.CKM_AES_GCM],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (Pkcs11Key tokenKey, byte[] peerKey) = EcExamples.AgreeAesKeyWithBclPeer(s);
                using (tokenKey)
                {
                    // The two keys are the same: what the token encrypts, the peer decrypts.
                    using var onToken = new AesGcmPkcs11(tokenKey, 16);
                    byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
                    onToken.Encrypt(nonce, Message, ciphertext, tag);
                    using var atPeer = new AesGcm(peerKey, 16);
                    byte[] decrypted = new byte[ciphertext.Length];
                    atPeer.Decrypt(nonce, ciphertext, tag, decrypted);
                    Assert.Equal(Message, decrypted);
                }

                // The BCL-shaped DeriveKey* methods return the shared secret into the process, which
                // the default policy refuses.
                using Pkcs11Key ec = s.GenerateEcKeyAgreementKeyPair();
                using var ecdh = new ECDiffieHellmanPkcs11(ec);
                using ECDiffieHellman other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                Assert.Throws<CryptoPolicyViolationException>(() => ecdh.DeriveKeyFromHash(other.PublicKey, HashAlgorithmName.SHA256));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),

        // Post-quantum (docs/examples/post-quantum.md)
        new(Pqc(nameof(PqcExamples.MlKemReceiveAesKey)), [typeof(MLKemPkcs11)],
            [CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            AssertMlKemReceiveAesKey, Unsupported: ExampleGates.ClassicAesGcm),
        new(Pqc(nameof(PqcExamples.MlDsaSign)), [typeof(MLDsaPkcs11)], [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                if (!b.SupportsMlDsa) Assert.Skip("The backend cannot operate ML-DSA.");
                (byte[] signature, byte[] publicKey) = PqcExamples.MlDsaSign(s, Message);
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(PqcExamples.MlDsaVerifyWithBcl(Message, signature, publicKey));
                Assert.False(PqcExamples.MlDsaVerifyWithBcl([.. Message, 0], signature, publicKey));
            })),
        new(Pqc(nameof(PqcExamples.MlDsaVerifyWithBcl)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL.");
                using MLDsa bcl = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                Assert.True(PqcExamples.MlDsaVerifyWithBcl(Message, bcl.SignData(Message), bcl.ExportMLDsaPublicKey()));
            }),
#pragma warning disable SYSLIB5006 // SlhDsa and SlhDsaPkcs11 are [Experimental] in .NET 10
        new(Pqc(nameof(PqcExamples.SlhDsaSign)), [typeof(SlhDsaPkcs11)], [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA],
            ExampleBackend.BouncyHsm,
            b => WithSession(b, s =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey) = PqcExamples.SlhDsaSign(s, Message);
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                using SlhDsa verifier = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, publicKey);
                Assert.True(verifier.VerifyData(Message, signature));
            })),
#pragma warning restore SYSLIB5006

        // Hashes and HMAC (docs/examples/hashes.md)
        new(Hash(nameof(HashExamples.Sha2OnToken)), [typeof(SHA256Pkcs11), typeof(SHA384Pkcs11), typeof(SHA512Pkcs11)],
            [CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(
                [SHA256.HashData(Message), SHA384.HashData(Message), SHA512.HashData(Message)],
                HashExamples.Sha2OnToken(s, Message)))),
        new(Hash(nameof(HashExamples.Sha3OnToken)), [typeof(SHA3_256Pkcs11), typeof(SHA3_384Pkcs11), typeof(SHA3_512Pkcs11)],
            [CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512], ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                byte[][] onToken = HashExamples.Sha3OnToken(s, Message);
                if (!SHA3_256.IsSupported) Assert.Skip("SHA-3 is not supported by this platform's BCL; the token side ran.");
                Assert.Equal([SHA3_256.HashData(Message), SHA3_384.HashData(Message), SHA3_512.HashData(Message)], onToken);
            })),
        new(Hash(nameof(HashExamples.BclSha256)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(SHA256.HashData(Message), HashExamples.BclSha256(Message))),
        new(Hash(nameof(HashExamples.GenerateHmacKey)), [typeof(HMACPkcs11)], [CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA256_HMAC],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                using Pkcs11Key key = HashExamples.GenerateHmacKey(s);
                byte[] tag = HashExamples.HmacSha256(key, Message);
                Assert.Equal(32, tag.Length);
                Assert.Equal(tag, HashExamples.HmacSha256(key, Message));
            })),
        new(Hash(nameof(HashExamples.HmacSha256)), [typeof(HMACPkcs11)], [CKM.CKM_SHA256_HMAC],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                // A known key, imported, so the token's HMAC can be compared with the BCL's.
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(raw).Sign().Verify().Build();
                using Pkcs11Key key = s.ImportKey(template);
                Assert.Equal(HashExamples.BclHmacSha256(raw, Message), HashExamples.HmacSha256(key, Message));
            })),
        new(Hash(nameof(HashExamples.BclHmacSha256)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                Assert.Equal(HMACSHA256.HashData(raw, Message), HashExamples.BclHmacSha256(raw, Message));
            }),

        // Key derivation (docs/examples/key-derivation.md)
        new(Kdf(nameof(KdfExamples.HkdfDeriveAesKey)), [typeof(HkdfPkcs11)], [CKM.CKM_HKDF_DERIVE, CKM.CKM_AES_GCM],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                byte[] ikm = RandomNumberGenerator.GetBytes(32), salt = RandomNumberGenerator.GetBytes(32), info = "example"u8.ToArray();
                using Pkcs11Key ikmKey = ImportDeriveKey(s, ikm);
                using Pkcs11Key derived = KdfExamples.HkdfDeriveAesKey(ikmKey, salt, info);
                AssertSameAesKey(derived, KdfExamples.BclHkdf(ikm, salt, info));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Kdf(nameof(KdfExamples.BclHkdf)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(32, KdfExamples.BclHkdf(new byte[32], new byte[16], []).Length)),
        new(Kdf(nameof(KdfExamples.Pbkdf2DeriveAesKey)), [typeof(Rfc2898DeriveBytesPkcs11)], [CKM.CKM_PKCS5_PBKD2, CKM.CKM_AES_GCM],
            ExampleBackend.Nss,
            b => WithSession(b, s =>
            {
                byte[] salt = RandomNumberGenerator.GetBytes(16);
                using var password = new SecurePassword("correct horse battery staple".AsSpan());
                using Pkcs11Key derived = KdfExamples.Pbkdf2DeriveAesKey(s, password, salt);
                AssertSameAesKey(derived, KdfExamples.BclPbkdf2("correct horse battery staple"u8.ToArray(), salt));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Kdf(nameof(KdfExamples.BclPbkdf2)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(
                Rfc2898DeriveBytes.Pbkdf2("pw"u8, new byte[16], 600_000, HashAlgorithmName.SHA256, 32),
                KdfExamples.BclPbkdf2("pw"u8.ToArray(), new byte[16]))),
        new(Kdf(nameof(KdfExamples.Sp800108DeriveAesKey)), [typeof(SP800108HmacCounterKdfPkcs11)],
            [CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SHA256_HMAC, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                byte[] kdk = RandomNumberGenerator.GetBytes(32);
                using Pkcs11Key kdkKey = ImportDeriveKey(s, kdk);
                using Pkcs11Key derived = KdfExamples.Sp800108DeriveAesKey(kdkKey, "orders"u8.ToArray(), "tenant-42"u8.ToArray());
                AssertSameAesKey(derived, KdfExamples.BclSp800108(kdk, "orders"u8.ToArray(), "tenant-42"u8.ToArray()));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Kdf(nameof(KdfExamples.BclSp800108)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(32, KdfExamples.BclSp800108(new byte[32], [1], [2]).Length)),

        // Certificates (docs/examples/certificates.md)
        new(Cert(nameof(CertificateExamples.IssueSelfSignedCertificate)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                string label = $"example-{Guid.NewGuid():N}";
                using Pkcs11Certificate stored = CertificateExamples.IssueSelfSignedCertificate(s, label);
                Assert.Equal("CN=Example Signing", stored.Certificate.Subject);
                Assert.False(stored.Certificate.HasPrivateKey);
            })),
        new(Cert(nameof(CertificateExamples.SignWithCertificateKey)), [typeof(Pkcs11CertificateExtensions)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                string label = $"example-{Guid.NewGuid():N}";
                using (CertificateExamples.IssueSelfSignedCertificate(s, label)) { }
                (byte[] signature, X509Certificate2 certificate) = CertificateExamples.SignWithCertificateKey(s, label, Message);
                using (certificate)
                using (ECDsa verifier = certificate.GetECDsaPublicKey()!)
                    Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256));
            })),
    ];

    private static string Cert(string method) => $"{nameof(CertificateExamples)}.{method}";

    private static string Kdf(string method) => $"{nameof(KdfExamples)}.{method}";

    // A known secret imported as a derive-only generic secret, so a token KDF can be compared with the BCL's.
    private static Pkcs11Key ImportDeriveKey(Pkcs11Session session, byte[] raw)
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(raw).Derive().Build();
        return session.ImportKey(template);
    }

    // The token key and the BCL's key bytes are the same key when what one encrypts, the other decrypts.
    private static void AssertSameAesKey(Pkcs11Key tokenKey, byte[] bclKey)
    {
        using var onToken = new AesGcmPkcs11(tokenKey, 16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
        onToken.Encrypt(nonce, Message, ciphertext, tag);
        using var inSoftware = new AesGcm(bclKey, 16);
        byte[] decrypted = new byte[ciphertext.Length];
        inSoftware.Decrypt(nonce, ciphertext, tag, decrypted);
        Assert.Equal(Message, decrypted);
    }

    private static string Hash(string method) => $"{nameof(HashExamples)}.{method}";

    private static string Pqc(string method) => $"{nameof(PqcExamples)}.{method}";

    private static void AssertMlKemReceiveAesKey(IPkcs11Backend backend)
    {
        if (!backend.SupportsMlKem) Assert.Skip("The backend cannot operate ML-KEM.");
        if (!MLKem.IsSupported) Assert.Skip("ML-KEM is not supported by this platform's BCL (the sender side).");
        using Pkcs11Session session = backend.OpenSession();
        (Pkcs11Key tokenKey, byte[] senderKey) = PqcExamples.MlKemReceiveAesKey(session);
        using (tokenKey)
        {
            // The sender encrypts with its copy of the shared secret; the token decrypts with its own.
            using var atSender = new AesGcm(senderKey, 16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
            atSender.Encrypt(nonce, Message, ciphertext, tag);
            using var onToken = new AesGcmPkcs11(tokenKey, 16);
            byte[] decrypted = new byte[ciphertext.Length];
            onToken.Decrypt(nonce, ciphertext, tag, decrypted);
            Assert.Equal(Message, decrypted);
        }
    }

    private static string Rsa(string method) => $"{nameof(RsaExamples)}.{method}";

    private static void AssertCbcPadUnderReviewedPolicy(IPkcs11Backend backend)
    {
        using (var pin = new SecurePin(backend.UserPin.Span))
            Assert.Equal(Message, AesModeExamples.CbcPadUnderReviewedPolicy(backend.Library, backend.TokenLabel, pin, Message));

        // Without the example's policy step, the default Recommended policy refuses the same call.
        using Pkcs11Session session = backend.OpenSession();
        using Pkcs11Key key = session.GenerateAesKey();
        using var aes = new AesPkcs11(key);
        Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(Message, new byte[16], System.Security.Cryptography.PaddingMode.PKCS7));
    }

    private static string Name(string aeadMethod) => $"{nameof(AeadExamples)}.{aeadMethod}";

    // Opens a session the backend's way (login or not) and runs an example in it.
    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11Session> body)
    {
        using Pkcs11Session session = backend.OpenSession();
        body(session);
    }

    /// <summary>The example names, as theory data (a name serializes; a delegate does not).</summary>
    public static TheoryData<string> Names => [.. All.Select(c => c.Name)];

    public static ExampleCase Get(string name) =>
        All.SingleOrDefault(c => c.Name == name) ?? throw new ArgumentException($"No example named {name}.", nameof(name));

    private static void AssertReadPinFromEnvironment(IPkcs11Backend backend)
    {
        string variable = $"KL_EXAMPLE_PIN_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(variable, Encoding.UTF8.GetString(backend.UserPin.Span));
        try
        {
            using SecurePin pin = GettingStartedExamples.ReadPinFromEnvironment(variable);
            using Pkcs11Session session = backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, pin);
            Assert.Equal(16, session.GenerateRandom(16).Length);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        var unset = Assert.Throws<InvalidOperationException>(() => GettingStartedExamples.ReadPinFromEnvironment(variable));
        Assert.Contains(variable, unset.Message, StringComparison.Ordinal);
    }

    private static void AssertEncryptAndDecryptWithTokenKey(IPkcs11Backend backend)
    {
        using (var pin = new SecurePin(backend.UserPin.Span))
            Assert.Equal(Message, GettingStartedExamples.EncryptAndDecryptWithTokenKey(backend.LibraryPath, backend.TokenLabel, pin, Message));

        // The example loaded the module a second time and disposed it: the fixture's own library must
        // still work, so disposing the example's instance did not finalize the module under it.
        using Pkcs11Session session = backend.OpenSession();
        Assert.Equal(16, session.GenerateRandom(16).Length);
    }
}
