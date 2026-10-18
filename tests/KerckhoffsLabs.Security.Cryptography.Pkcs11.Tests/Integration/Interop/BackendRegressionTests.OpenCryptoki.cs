using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BackendRegression over opencryptoki — thin wrapper over <see cref="BackendRegressionTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class BackendRegressionTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EcdhRawSecret_WithLeadingZeroBytes_KeepsThem() => BackendRegressionTestCases.Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable() => BackendRegressionTestCases.Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetAttributeValue_MixedTemplate_FillsTheReadableEntries() => BackendRegressionTestCases.Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesGcm_ClassicParameters_MatchBcl() => BackendRegressionTestCases.Assert_AesGcm_ClassicParameters_MatchBcl(_backend);
}
