using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>CkmAesCtrParams over SoftHSM2 — thin wrapper over <see cref="AesCtrParamsTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class AesCtrParamsTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.Rows), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.RowsUsingTheLastCounterValue), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_UsingTheLastCounterValue_MatchesTheBclCtr(int counterBits, string blockHex, int length)
    {
        AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);
    }
}
