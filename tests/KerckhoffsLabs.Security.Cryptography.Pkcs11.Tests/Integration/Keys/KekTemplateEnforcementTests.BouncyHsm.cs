using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KekTemplateEnforcement over BouncyHsm — thin wrapper over <see cref="KekTemplateEnforcementTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class KekTemplateEnforcementTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Wrap_SensitiveTargetKey_Succeeds() => KekTemplateEnforcementTestCases.Assert_Wrap_SensitiveTargetKey_Succeeds(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Wrap_NonSensitiveTargetKey_Throws() => KekTemplateEnforcementTestCases.Assert_Wrap_NonSensitiveTargetKey_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Unwrap_ExplicitMatchingTemplate_Succeeds() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Unwrap_ExplicitConflictingTemplate_Throws() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitConflictingTemplate_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Unwrap_OmittedAttributeTemplate_TreatsAsInherited() => KekTemplateEnforcementTestCases.Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(_backend);
}
