using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KekTemplateEnforcement over wolfPKCS11 — thin wrapper over <see cref="KekTemplateEnforcementTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class KekTemplateEnforcementTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void Wrap_SensitiveTargetKey_Succeeds() => KekTemplateEnforcementTestCases.Assert_Wrap_SensitiveTargetKey_Succeeds(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void Wrap_NonSensitiveTargetKey_Throws() => KekTemplateEnforcementTestCases.Assert_Wrap_NonSensitiveTargetKey_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void Unwrap_ExplicitMatchingTemplate_Succeeds() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void Unwrap_ExplicitConflictingTemplate_Throws() => KekTemplateEnforcementTestCases.Assert_Unwrap_ExplicitConflictingTemplate_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void Unwrap_OmittedAttributeTemplate_TreatsAsInherited() => KekTemplateEnforcementTestCases.Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(_backend);
}
