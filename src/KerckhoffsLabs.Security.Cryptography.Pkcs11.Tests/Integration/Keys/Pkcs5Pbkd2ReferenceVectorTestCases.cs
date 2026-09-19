using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Independent-reference proof for every <c>CKP_PKCS5_PBKD2_HMAC_*</c> PRF Kryoptic and NSS
/// implement, going straight through <see cref="Pkcs11Session"/> and <see cref="CkmPkcs5Pbkd2Params"/>
/// rather than the <see cref="Rfc2898DeriveBytesPkcs11"/> façade (whose <c>PrfForHash</c> switch has no
/// SHA-224 case to call through at all, and doesn't reach Kryoptic's two NSS-incompatible PRFs either).
/// For SHA-1/256/384/512, <see cref="Algorithms.Rfc2898DeriveBytesPkcs11TestCases"/> already
/// cross-checks each backend against the BCL's <c>Rfc2898DeriveBytes.Pbkdf2</c> through that façade;
/// this is a second, independent check along a different path, so it can catch a façade-layer bug the
/// BCL comparison alone couldn't distinguish from a backend bug. For SHA-224 (and, on Kryoptic,
/// SHA-512/224 and SHA-512/256) this is the *only* correctness check that exists anywhere:
/// <c>Rfc2898DeriveBytes.Pbkdf2</c> has no SHA-224 support at all (no <c>HashAlgorithmName.SHA224</c>,
/// and a manually-constructed <c>new HashAlgorithmName("SHA224")</c> throws
/// <c>CryptographicException</c>), and NSS doesn't implement the two truncated-SHA-512 PRFs, so
/// neither the BCL nor a second vendored backend is available to verify against.
/// <para>
/// Each backend is checked independently against a reference vector computed with CPython's hashlib
/// (OpenSSL-backed) -- run live in this sandbox while writing this test, not from memory or any
/// AI-generated source, and reproducible with:
/// <code>
/// python3 -c "import hashlib,binascii; print(binascii.hexlify(hashlib.pbkdf2_hmac(
///     'sha1', b'correct horse battery staple', b'cross-backend-sha1-salt', 10000, dklen=20)).decode())"
/// </code>
/// (same shape for the other PRFs below, substituting the hashlib name, salt, and dklen).
/// </para>
/// <para>
/// Deliberately <b>not</b> a live Kryoptic-vs-NSS comparison in one test: that would need both
/// backend fixtures constructed in the same process, and <see cref="KryopticBackendFixture"/>
/// recreates a single fixed on-disk SQLite file on construction (not one path per instance) --
/// unioning it into a second xUnit collection alongside the existing "Kryoptic" collection created a
/// second, independent fixture instance that could run concurrently with the first (different
/// collections run in parallel by default), racing on that same file and corrupting shared token
/// state for the entire "Kryoptic" collection. An earlier version of this test did exactly that and
/// caused ~130 unrelated Kryoptic test failures under xUnit's parallel collection scheduling. Comparing
/// against an independent reference instead of a second live backend avoids the hazard entirely, and
/// is exactly the same shape already used for Kryoptic's two NSS-incompatible PRFs.
/// </para>
/// </summary>
internal static class Pkcs5Pbkd2ReferenceVectorTestCases
{
    private const string Password = "correct horse battery staple";
    private const ulong Iterations = 10_000;

    // (prf, salt, expectedHex, outputLength)
    public static TheoryData<CKP, string, string, int> SharedPrfs =>
    [
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, "cross-backend-sha1-salt",
            "f4cbbcd88e26ce0a187bb5cf22f9a876e80186cf", 20),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA224, "cross-backend-sha224-salt",
            "b9e375cb05536bb2bbfb65c1ae7ca5fe4ca0950cdc03706f62c1fbd9", 28),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, "cross-backend-sha256-salt",
            "5d0a000748aa522bbabb9696a15ae4f883348cf15eafb1b2933081536edcdc90", 32),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA384, "cross-backend-sha384-salt",
            "031b19ab60547c1dd85ab76d95831f815c20c3d655a049f20c137ab3311d5c4b24cc9d509f7cd8393d5299b81a0783b5", 48),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512, "cross-backend-sha512-salt",
            "6f5fc99ca6b1c1e4103e10a4499d64966865556bf2fe14f05ae623f586da3aa356c80dade6df377fc8d2775dad2daac4e21c2b0a269c64546b684e4172de610d", 64),
    ];

    // Kryoptic-only: NSS doesn't implement these two, so there's no second backend to compare
    // against either -- same reasoning as SharedPrfs, just also excluded from a cross-backend design.
    public static TheoryData<CKP, string, string, int> KryopticOnlyPrfs =>
    [
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_224, "cross-backend-sha512-224-salt",
            "c45a11891acc4bdeb4199302f5cc60f70ea1c6051a04a97d1a2ef24e", 28),
        (CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256, "cross-backend-sha512-256-salt",
            "b1110ea6ce4eba55d771417cbe5465bc1338c1d52293b63ad338d83352b039c7", 32),
    ];

    internal static void Assert_MatchesIndependentReference(IPkcs11Backend backend, CKP prf, string salt, string expectedHex, int outputLength)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        byte[] actual = Derive(backend, prf, salt, outputLength);
        Assert.Equal(Convert.FromHexString(expectedHex), actual);
    }

    private static byte[] Derive(IPkcs11Backend backend, CKP prf, string salt, int outputLength)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_PKCS5_PBKD2,
                new CkmPkcs5Pbkd2Params(Encoding.UTF8.GetBytes(salt), Iterations, prf, Encoding.UTF8.GetBytes(Password)));

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
