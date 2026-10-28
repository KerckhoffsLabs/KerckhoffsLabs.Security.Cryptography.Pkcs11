using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>AesCmac over FreeHSM — thin wrapper over <see cref="AesCmacTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class AesCmacTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Sign_MatchesRfc4493(int length, string expectedMac) => AesCmacTestCases.Assert_Sign_MatchesRfc4493(_backend, length, expectedMac);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Verify_AcceptsRfc4493_RejectsAlteredMac(int length, string expectedMac) => AesCmacTestCases.Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(_backend, length, expectedMac);
}
