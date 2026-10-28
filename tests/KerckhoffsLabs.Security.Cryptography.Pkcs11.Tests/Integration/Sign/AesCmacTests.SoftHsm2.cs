using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>AesCmac over SoftHsm2 — thin wrapper over <see cref="AesCmacTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class AesCmacTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Sign_MatchesRfc4493(int length, string expectedMac) => AesCmacTestCases.Assert_Sign_MatchesRfc4493(_backend, length, expectedMac);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Verify_AcceptsRfc4493_RejectsAlteredMac(int length, string expectedMac) => AesCmacTestCases.Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(_backend, length, expectedMac);
}
