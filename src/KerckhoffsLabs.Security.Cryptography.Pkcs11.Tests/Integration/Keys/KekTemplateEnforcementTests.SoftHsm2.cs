using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KekTemplateEnforcement over SoftHsm — thin wrapper over <see cref="KekTemplateEnforcementTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class KekTemplateEnforcementTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Wrap_SensitiveTargetKey_Succeeds() => KekTemplateEnforcementTestCases.Assert_Wrap_SensitiveTargetKey_Succeeds(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Wrap_NonSensitiveTargetKey_Throws() => KekTemplateEnforcementTestCases.Assert_Wrap_NonSensitiveTargetKey_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Unwrap_ExplicitMatchingTemplate_Succeeds() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Unwrap_ExplicitConflictingTemplate_Throws() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitConflictingTemplate_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Unwrap_OmittedAttributeTemplate_TreatsAsInherited() => KekTemplateEnforcementTestCases.Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(_backend);
}
