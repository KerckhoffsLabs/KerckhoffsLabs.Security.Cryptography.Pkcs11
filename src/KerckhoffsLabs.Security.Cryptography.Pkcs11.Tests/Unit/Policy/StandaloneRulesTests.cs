using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class StandaloneRulesTests
{
    [Theory]
    [InlineData(2047, false)]
    [InlineData(2048, true)]
    [InlineData(4096, true)]
    public void RsaModulusMinimum_DeniesBelowTheFloor(int bits, bool allowed)
    {
        PolicyDecision d = RsaKeyGenerationRule.Minimum(2048).Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, bits));
        Assert.Equal(allowed, d.IsAllowed);
        if (!allowed) Assert.Equal($"RSA-{bits} is below this policy's 2048-bit minimum.", d.Reason);
    }

    [Fact]
    public void RsaModulusMinimum_RationaleNamesTheFloor() =>
        Assert.Equal("RSA key generation requires a modulus of at least 3072 bits.", RsaKeyGenerationRule.Minimum(3072).Rationale);

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RsaModulusMinimum_RejectsANonPositiveFloor(int bits) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => RsaKeyGenerationRule.Minimum(bits));

    [Fact]
    public void RequireSensitive_RefusesOnlyAFalseSensitiveAttribute()
    {
        KeyTemplateRule rule = KeyTemplateRule.RequireSensitive();
        using var f = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var t = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        Assert.False(rule.Evaluate(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [f])).IsAllowed);
        Assert.True(rule.Evaluate(new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [t])).IsAllowed);
        Assert.True(rule.Evaluate(new KeyTemplateRequest(null, [])).IsAllowed);
    }

    [Theory]
    [InlineData(SecretExportKind.EcdhSharedSecret)]
    [InlineData(SecretExportKind.KemSharedSecret)]
    [InlineData(SecretExportKind.KdfOutput)]
    public void Refuse_DeniesEveryExportKind(SecretExportKind kind) =>
        Assert.False(SecretExportRule.Refuse().Evaluate(new SecretExportRequest(kind), new PolicyIdentity("App", null)).IsAllowed);
}
