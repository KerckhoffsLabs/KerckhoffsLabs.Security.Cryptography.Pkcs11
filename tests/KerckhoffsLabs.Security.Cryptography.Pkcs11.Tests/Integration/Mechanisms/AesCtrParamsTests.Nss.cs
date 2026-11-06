using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>CkmAesCtrParams over NSS softoken — thin wrapper over <see cref="AesCtrParamsTestCases"/>.</summary>
[Collection("Nss")]
public sealed class AesCtrParamsTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.Rows), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.RowsUsingTheLastCounterValue), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_UsingTheLastCounterValue_MatchesTheBclCtr(int counterBits, string blockHex, int length)
    {
        AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);
    }
}
