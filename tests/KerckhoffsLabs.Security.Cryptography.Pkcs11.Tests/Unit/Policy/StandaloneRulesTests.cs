using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

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
    [InlineData(KeyMaterialExportKind.EcdhSharedSecret)]
    [InlineData(KeyMaterialExportKind.KemSharedSecret)]
    [InlineData(KeyMaterialExportKind.KdfOutput)]
    public void Refuse_DeniesEveryExportKind(KeyMaterialExportKind kind) =>
        Assert.False(KeyMaterialExportRule.Refuse().Evaluate(new KeyMaterialExportRequest(kind)).IsAllowed);

    [Fact]
    public void KeyMaterialExportAllow_AllowsOnlyTheNamedKinds()
    {
        KeyMaterialExportRule rule = KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput], "r");
        Assert.True(rule.Evaluate(new KeyMaterialExportRequest(KeyMaterialExportKind.KdfOutput)).IsAllowed);
        foreach (KeyMaterialExportKind other in new[] { KeyMaterialExportKind.EcdhSharedSecret, KeyMaterialExportKind.KemSharedSecret })
        {
            PolicyDecision d = rule.Evaluate(new KeyMaterialExportRequest(other));
            Assert.False(d.IsAllowed);
            Assert.Equal(KeyMaterialExportRule.Refuse().Evaluate(new KeyMaterialExportRequest(other)).Reason, d.Reason);
        }
    }

    [Fact]
    public void KeyMaterialExportAllow_CopiesTheKindsAtCallTime()
    {
        var kinds = new List<KeyMaterialExportKind> { KeyMaterialExportKind.KdfOutput };
        KeyMaterialExportRule rule = KeyMaterialExportRule.Allow(kinds, "r");
        kinds.Add(KeyMaterialExportKind.EcdhSharedSecret);
        Assert.False(rule.Evaluate(new KeyMaterialExportRequest(KeyMaterialExportKind.EcdhSharedSecret)).IsAllowed);
    }

    [Fact]
    public void KeyMaterialExportAllow_EmptyKinds_Throws() =>
        Assert.Throws<ArgumentException>(() => KeyMaterialExportRule.Allow([], "r"));

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void KeyMaterialExportAllow_BlankRationale_Throws(string rationale) =>
        Assert.Throws<ArgumentException>(() => KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput], rationale));

    [Fact]
    public void KeyMaterialExportAllow_UndefinedKind_Throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyMaterialExportRule.Allow([(KeyMaterialExportKind)99], "r"));

    [Fact]
    public void KeyMaterialExportAllow_RationaleAppearsInCatalogue()
    {
        ComposedCryptoPolicy policy = new CryptoPolicyBuilder("Custom")
            .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput, KeyMaterialExportKind.KemSharedSecret], "HKDF in managed code"))
            .Build();
        string rationale = policy.Catalogue.KeyMaterialExport.Rationale;
        Assert.Contains("HKDF in managed code", rationale);
        Assert.Contains("KdfOutput", rationale);
        Assert.Contains("KemSharedSecret", rationale);
    }
}
