using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BackendRegression over BouncyHsm — thin wrapper over <see cref="BackendRegressionTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class BackendRegressionTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdhRawSecret_WithLeadingZeroBytes_KeepsThem() => BackendRegressionTestCases.Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable() => BackendRegressionTestCases.Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GetAttributeValue_MixedTemplate_FillsTheReadableEntries() => BackendRegressionTestCases.Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_ClassicParameters_MatchBcl() => BackendRegressionTestCases.Assert_AesGcm_ClassicParameters_MatchBcl(_backend);
}
