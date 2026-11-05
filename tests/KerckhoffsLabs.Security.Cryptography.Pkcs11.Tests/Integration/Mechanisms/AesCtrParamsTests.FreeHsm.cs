using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>CkmAesCtrParams over FreeHSM — thin wrapper over <see cref="AesCtrParamsTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class AesCtrParamsTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.Rows), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.RowsUsingTheLastCounterValue), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_UsingTheLastCounterValue_MatchesTheBclCtr(int counterBits, string blockHex, int length)
    {
        AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);
    }
}
