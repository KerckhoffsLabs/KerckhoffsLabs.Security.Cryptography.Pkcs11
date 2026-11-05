using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BackendRegression over wolfPKCS11 — thin wrapper over <see cref="BackendRegressionTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class BackendRegressionTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void EcdhRawSecret_WithLeadingZeroBytes_KeepsThem() => BackendRegressionTestCases.Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable() => BackendRegressionTestCases.Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetAttributeValue_MixedTemplate_FillsTheReadableEntries() => BackendRegressionTestCases.Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesGcm_ClassicParameters_MatchBcl() => BackendRegressionTestCases.Assert_AesGcm_ClassicParameters_MatchBcl(_backend);
}
