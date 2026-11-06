using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KekTemplateEnforcement over NSS softoken — thin wrapper over <see cref="KekTemplateEnforcementTestCases"/>.</summary>
[Collection("Nss")]
public sealed class KekTemplateEnforcementTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Wrap_SensitiveTargetKey_Succeeds() => KekTemplateEnforcementTestCases.Assert_Wrap_SensitiveTargetKey_Succeeds(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.KekTemplateEnforcementAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS does not enforce a wrapping key\'s CKA_WRAP_TEMPLATE or CKA_UNWRAP_TEMPLATE")]
    public void Wrap_NonSensitiveTargetKey_Throws() => KekTemplateEnforcementTestCases.Assert_Wrap_NonSensitiveTargetKey_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_ExplicitMatchingTemplate_Succeeds() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.KekTemplateEnforcementAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS does not enforce a wrapping key\'s CKA_WRAP_TEMPLATE or CKA_UNWRAP_TEMPLATE")]
    public void Unwrap_ExplicitConflictingTemplate_Throws() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitConflictingTemplate_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_OmittedAttributeTemplate_TreatsAsInherited() => KekTemplateEnforcementTestCases.Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(_backend);
}
