using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KekTemplateEnforcement over opencryptoki — thin wrapper over <see cref="KekTemplateEnforcementTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class KekTemplateEnforcementTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Wrap_SensitiveTargetKey_Succeeds() => KekTemplateEnforcementTestCases.Assert_Wrap_SensitiveTargetKey_Succeeds(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Wrap_NonSensitiveTargetKey_Throws() => KekTemplateEnforcementTestCases.Assert_Wrap_NonSensitiveTargetKey_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Unwrap_ExplicitMatchingTemplate_Succeeds() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Unwrap_ExplicitConflictingTemplate_Throws() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitConflictingTemplate_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Unwrap_OmittedAttributeTemplate_TreatsAsInherited() => KekTemplateEnforcementTestCases.Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(_backend);
}
