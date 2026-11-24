using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>HSS (CKM_HSS) over BouncyHsm — thin wrapper over <see cref="HssTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class HssTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(1)]
    [InlineData(2)]
    public void SignVerify_RoundTrips(int levels) => HssTestCases.Assert_Hss_SignVerify_RoundTrips(_backend, levels);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EachSignature_UsesTheNextOneTimeKey() => HssTestCases.Assert_Hss_EachSignatureUsesTheNextOneTimeKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExhaustedKey_IsRefused() => HssTestCases.Assert_Hss_ExhaustedKey_IsRefused(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void PrivateKey_IsSensitiveAndUnextractable() => HssTestCases.Assert_Hss_PrivateKey_IsSensitiveAndUnextractable(_backend);
}
