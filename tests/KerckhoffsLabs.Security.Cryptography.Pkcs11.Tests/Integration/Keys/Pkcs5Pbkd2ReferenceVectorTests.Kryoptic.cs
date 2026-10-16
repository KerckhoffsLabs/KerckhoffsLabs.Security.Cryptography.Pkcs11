using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Pkcs5Pbkd2ReferenceVectorTests over Kryoptic -- thin wrapper over
/// <see cref="Pkcs5Pbkd2ReferenceVectorTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class Pkcs5Pbkd2ReferenceVectorTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.SharedPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void SharedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.KryopticOnlyPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void KryopticOnlyPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);
}
