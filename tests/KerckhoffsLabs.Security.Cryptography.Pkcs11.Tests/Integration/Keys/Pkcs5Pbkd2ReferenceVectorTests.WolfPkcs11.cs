using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Pkcs5Pbkd2ReferenceVectorTests over wolfPKCS11 -- thin wrapper over
/// <see cref="Pkcs5Pbkd2ReferenceVectorTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class Pkcs5Pbkd2ReferenceVectorTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.SharedPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void SharedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.KryopticOnlyPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void Sha512TruncatedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);
}
