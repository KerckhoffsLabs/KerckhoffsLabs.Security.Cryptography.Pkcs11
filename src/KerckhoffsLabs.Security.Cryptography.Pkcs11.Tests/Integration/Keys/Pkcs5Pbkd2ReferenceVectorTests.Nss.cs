using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Pkcs5Pbkd2ReferenceVectorTests over NSS -- thin wrapper over
/// <see cref="Pkcs5Pbkd2ReferenceVectorTestCases"/>.</summary>
[Collection("Nss")]
public sealed class Pkcs5Pbkd2ReferenceVectorTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(Pkcs5Pbkd2ReferenceVectorTestCases.SharedPrfs), MemberType = typeof(Pkcs5Pbkd2ReferenceVectorTestCases))]
    public void SharedPrf_MatchesIndependentReference(CKP prf, string salt, string expectedHex, int outputLength) =>
        Pkcs5Pbkd2ReferenceVectorTestCases.Assert_MatchesIndependentReference(_backend, prf, salt, expectedHex, outputLength);
}
