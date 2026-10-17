using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BackendRegression over SoftHsm — thin wrapper over <see cref="BackendRegressionTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class BackendRegressionTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EcdhRawSecret_WithLeadingZeroBytes_KeepsThem() => BackendRegressionTestCases.Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable() => BackendRegressionTestCases.Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GetAttributeValue_MixedTemplate_FillsTheReadableEntries() => BackendRegressionTestCases.Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesGcm_ClassicParameters_MatchBcl() => BackendRegressionTestCases.Assert_AesGcm_ClassicParameters_MatchBcl(_backend);
}
