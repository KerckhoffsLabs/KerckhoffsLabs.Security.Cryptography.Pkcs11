using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Pkcs5Pbkd2ReferenceVectorTests over FreeHSM -- thin wrapper over
/// <see cref="Pkcs5Pbkd2ReferenceVectorTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class Pkcs5Pbkd2ReferenceVectorTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.SharedPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void SharedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.KryopticOnlyPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void Sha512TruncatedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);
}
