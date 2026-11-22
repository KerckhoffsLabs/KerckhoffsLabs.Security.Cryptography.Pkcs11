using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public class KeyStrengthRuleTests
{
    private static ComposedCryptoPolicy Inspecting() =>
        new CryptoPolicyBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(
                r => r.ValueLengthBytes == 32 ? PolicyDecision.Allow : PolicyDecision.Deny("short"), "AES-256 only"))
            .Build();

    [Theory]
    [InlineData("Recommended")]
    [InlineData("NistApproved")]
    public void BuiltIns_AllowEveryKeyStrengthRequest_AndDoNotInspect(string name)
    {
        ComposedCryptoPolicy p = name == "Recommended" ? CryptoPolicy.Recommended : CryptoPolicy.NistApproved;
        Assert.False(p.InspectsKeys);
        Assert.True(p.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ValueLengthBytes = 16 }).IsAllowed);
        Assert.True(p.Evaluate(new KeyStrengthRequest(null, KeyStrengthSource.CreatedKey)).IsAllowed);
    }

    [Fact]
    public void FromDelegate_Inspects_AndDecides()
    {
        ComposedCryptoPolicy p = Inspecting();
        Assert.True(p.InspectsKeys);
        Assert.Equal("short", p.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.Template) { ValueLengthBytes = 16 }).Reason);
        Assert.True(p.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.Template) { ValueLengthBytes = 32 }).IsAllowed);
    }

    [Fact]
    public void ToBuilder_KeepsTheKeyStrengthRule()
    {
        ComposedCryptoPolicy u = Inspecting().ToBuilder("U").Build();
        Assert.True(u.InspectsKeys);
        Assert.Equal("short", u.Evaluate(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.Template) { ValueLengthBytes = 16 }).Reason);
    }

    [Fact]
    public void Describe_NamesTypeSizeAndSource_NeverValues()
        => Assert.Equal("CKK_AES key of 16 bytes (existing key)",
            new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ValueLengthBytes = 16 }.Describe());

    [Fact]
    public void Describe_NamesParameterSet_WhenTheKeyTypeMatches()
        => Assert.Equal("CKK_ML_KEM key, parameter set CKP_ML_KEM_768 (template)",
            new KeyStrengthRequest(CKK.CKK_ML_KEM, KeyStrengthSource.Template) { ParameterSet = (ulong)CkpMlKem.CKP_ML_KEM_768 }.Describe());

    [Fact]
    public void Describe_NamesMlDsaParameterSet()
        => Assert.Equal("CKK_ML_DSA key, parameter set CKP_ML_DSA_87 (existing key)",
            new KeyStrengthRequest(CKK.CKK_ML_DSA, KeyStrengthSource.ExistingKey) { ParameterSet = (ulong)CkpMlDsa.CKP_ML_DSA_87 }.Describe());

    [Fact]
    public void Describe_UsesHex_WhenTheParameterSetIsNotNameable()
        => Assert.Equal("CKK_AES key, parameter set 0x2A (existing key)",
            new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ParameterSet = 0x2A }.Describe());

    [Fact]
    public void Describe_UnknownType_AndHssLevels()
    {
        Assert.Equal("key of unknown type (created key)", new KeyStrengthRequest(null, KeyStrengthSource.CreatedKey).Describe());
        Assert.Equal("CKK_HSS key, 2 levels (existing key)",
            new KeyStrengthRequest(CKK.CKK_HSS, KeyStrengthSource.ExistingKey) { HssLevels = 2 }.Describe());
    }
}
