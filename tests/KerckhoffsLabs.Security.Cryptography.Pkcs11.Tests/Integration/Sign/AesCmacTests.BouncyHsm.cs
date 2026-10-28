using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>AesCmac over BouncyHsm — thin wrapper over <see cref="AesCmacTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class AesCmacTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    // No empty message: the server refuses to MAC one (its AesWrapperSigner takes no empty data, so
    // C_Sign and C_Verify give CKR_DATA_LEN_RANGE).
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493NonEmptyVectors), MemberType = typeof(AesCmacTestCases))]
    public void Sign_MatchesRfc4493(int length, string expectedMac) => AesCmacTestCases.Assert_Sign_MatchesRfc4493(_backend, length, expectedMac);

    // No empty message: the server refuses to MAC one (its AesWrapperSigner takes no empty data, so
    // C_Sign and C_Verify give CKR_DATA_LEN_RANGE).
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493NonEmptyVectors), MemberType = typeof(AesCmacTestCases))]
    public void Verify_AcceptsRfc4493_RejectsAlteredMac(int length, string expectedMac) => AesCmacTestCases.Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(_backend, length, expectedMac);
}
