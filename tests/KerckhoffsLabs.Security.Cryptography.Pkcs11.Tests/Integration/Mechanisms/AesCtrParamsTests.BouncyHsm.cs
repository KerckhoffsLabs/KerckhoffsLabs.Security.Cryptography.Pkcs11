using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>CkmAesCtrParams over BouncyHsm — thin wrapper over <see cref="AesCtrParamsTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class AesCtrParamsTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.Rows), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.RowsUsingTheLastCounterValue), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_UsingTheLastCounterValue_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);
}
