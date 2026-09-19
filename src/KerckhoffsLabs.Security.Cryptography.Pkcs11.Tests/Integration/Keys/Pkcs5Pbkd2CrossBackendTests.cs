using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>xUnit collection combining the Kryoptic and NSS backend fixtures, for the tests here
/// that need both real backends open at once to cross-check them against each other.</summary>
[CollectionDefinition("Kryoptic+Nss")]
public sealed class KryopticAndNssCollection : ICollectionFixture<KryopticBackendFixture>, ICollectionFixture<NssBackendFixture> { }

/// <summary>
/// Cross-backend proof for every <c>CKP_PKCS5_PBKD2_HMAC_*</c> PRF both Kryoptic and NSS implement
/// (SHA-1/224/256/384/512), plus Kryoptic's two extra PRFs (SHA-512/224, SHA-512/256) that NSS doesn't
/// implement, verified separately below against an independently computed reference instead of a
/// second backend. For SHA-1/256/384/512, <c>Rfc2898DeriveBytesPkcs11TestCases</c> already
/// cross-checks each backend individually against the BCL's <c>Rfc2898DeriveBytes.Pbkdf2</c> through
/// the <see cref="Rfc2898DeriveBytesPkcs11"/> façade; this is a second, independent check
/// along a different path (raw <see cref="Pkcs11Session"/> + <see cref="CkmPkcs5Pbkd2Params"/>,
/// bypassing that façade entirely), so it can catch a façade-layer bug the BCL comparison alone
/// couldn't distinguish from a backend bug. For SHA-224, this is the *only* correctness check that
/// exists anywhere: <c>Rfc2898DeriveBytes.Pbkdf2</c> has no SHA-224 support at all (no
/// <c>HashAlgorithmName.SHA224</c>, and a manually-constructed <c>new HashAlgorithmName("SHA224")</c>
/// throws <c>CryptographicException</c>), which is exactly why
/// <see cref="Rfc2898DeriveBytesPkcs11"/>'s <c>PrfForHash</c> excludes it too.
/// With no BCL reference available, two independent real implementations deriving the identical key
/// from identical inputs is the correctness check used elsewhere in this suite for mechanisms with no
/// BCL equivalent, and it's what this falls back to for SHA-1/224/256/384/512.
/// </summary>
[Collection("Kryoptic+Nss")]
public sealed class Pkcs5Pbkd2CrossBackendTests(KryopticBackendFixture kryoptic, NssBackendFixture nss)
{
    private readonly KryopticBackendFixture _kryoptic = kryoptic;
    private readonly NssBackendFixture _nss = nss;

    public static TheoryData<CKP, int> SharedPrfs =>
    [
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, 20),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA224, 28),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, 32),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA384, 48),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512, 64),
    ];

    [Theory]
    [MemberData(nameof(SharedPrfs))]
    public void KryopticAndNssDeriveIdenticalKey(CKP prf, int outputLength)
    {
        if (!KryopticBackendFixture.KryopticAvailable || !NssBackendFixture.NssAvailable)
            Assert.Skip("Requires both Kryoptic and NSS to be available.");

        _kryoptic.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        _nss.RequireMechanism(CKM.CKM_PKCS5_PBKD2);

        byte[] password = "correct horse battery staple"u8.ToArray();
        byte[] salt = Encoding.UTF8.GetBytes($"cross-backend-{prf}-salt");
        const ulong Iterations = 10_000;

        byte[] kryopticOutput = Derive(_kryoptic, prf, password, salt, Iterations, outputLength);
        byte[] nssOutput = Derive(_nss, prf, password, salt, Iterations, outputLength);

        Assert.Equal(kryopticOutput, nssOutput);
    }

    // Kryoptic-only: CKP_PKCS5_PBKD2_HMAC_SHA512_224/256 have no second vendored backend to
    // cross-check against (NSS doesn't implement them), so unlike
    // SharedPrfs above, these compare against an independently computed reference vector instead
    // of a second backend's output.
    //
    // Reference values computed just now with CPython's hashlib (OpenSSL-backed), not from memory
    // or any AI-generated source -- reproducible with:
    //   python3 -c "import hashlib,binascii; print(binascii.hexlify(hashlib.pbkdf2_hmac(
    //       'sha512_224', b'correct horse battery staple', b'cross-backend-sha512-224-salt',
    //       10000, dklen=28)).decode())"
    // (same shape for 'sha512_256', salt b'cross-backend-sha512-256-salt', dklen=32).
    public static TheoryData<CKP, string, string, int> Kryoptic512Prfs =>
    [
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_224, "cross-backend-sha512-224-salt",
            "c45a11891acc4bdeb4199302f5cc60f70ea1c6051a04a97d1a2ef24e", 28),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256, "cross-backend-sha512-256-salt",
            "b1110ea6ce4eba55d771417cbe5465bc1338c1d52293b63ad338d83352b039c7", 32),
    ];

    [Theory]
    [MemberData(nameof(Kryoptic512Prfs))]
    public void Kryoptic_Sha512TruncatedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength)
    {
        if (!KryopticBackendFixture.KryopticAvailable)
            Assert.Skip("Requires Kryoptic to be available.");
        _kryoptic.RequireMechanism(CKM.CKM_PKCS5_PBKD2);

        byte[] password = "correct horse battery staple"u8.ToArray();
        const ulong Iterations = 10_000;

        byte[] actual = Derive(_kryoptic, prf, password, Encoding.UTF8.GetBytes(salt), Iterations, outputLength);
        Assert.Equal(Convert.FromHexString(expectedHex), actual);
    }

    private static byte[] Derive(IPkcs11Backend backend, CKP prf, byte[] password, byte[] salt, ulong iterations, int outputLength)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_PKCS5_PBKD2,
                new CkmPkcs5Pbkd2Params(salt, iterations, prf, password));

            // Session-scoped, extractable, non-sensitive generic secret so CKA_VALUE can be read back --
            // the same template shape Rfc2898DeriveBytesPkcs11.DeriveExtractable uses.
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)outputLength);
            using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrValueLen, attrExtractable, attrSensitive };

            ObjectHandle derived;
            using (session.AllowInsecureScope())
                derived = session.GenerateKey(mechanism, template);
            try
            {
                using var attrs = session.GetAttributeValue(derived, [CKA.CKA_VALUE]);
                return attrs[0].GetValueAsByteArray();
            }
            finally { session.DestroyObject(derived); }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
            session.Dispose();
        }
    }
}
