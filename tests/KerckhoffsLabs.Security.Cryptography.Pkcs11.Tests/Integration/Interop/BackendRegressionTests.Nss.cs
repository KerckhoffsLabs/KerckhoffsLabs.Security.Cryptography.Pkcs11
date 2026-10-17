using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BackendRegression over NSS — thin wrapper over <see cref="BackendRegressionTestCases"/>.</summary>
[Collection("Nss")]
public sealed class BackendRegressionTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EcdhRawSecret_WithLeadingZeroBytes_KeepsThem() => BackendRegressionTestCases.Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable() => BackendRegressionTestCases.Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GetAttributeValue_MixedTemplate_FillsTheReadableEntries() => BackendRegressionTestCases.Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesGcm_ClassicParameters_MatchBcl() => BackendRegressionTestCases.Assert_AesGcm_ClassicParameters_MatchBcl(_backend);
}
