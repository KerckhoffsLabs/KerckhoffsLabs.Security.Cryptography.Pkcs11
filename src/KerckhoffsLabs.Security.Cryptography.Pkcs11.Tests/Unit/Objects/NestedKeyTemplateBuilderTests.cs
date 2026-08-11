using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

public sealed class NestedKeyTemplateBuilderTests
{
    /// <summary>
    /// The nested builder deliberately carries no secure defaults, unlike every other key builder.
    /// CKA_WRAP_TEMPLATE is a filter - "keys that do not match cannot be wrapped" - so injecting
    /// CKA_SENSITIVE would narrow which keys are wrappable in a way the caller never wrote.
    /// </summary>
    [Fact]
    public void Build_WithNothingConfigured_ProducesAnEmptyTemplate()
    {
        using var builder = new NestedKeyTemplateBuilder();

        using ObjectTemplate template = builder.Build();

        Assert.Equal(0, template.Count);
    }

    [Fact]
    public void Helpers_SetTheExpectedAttributes()
    {
        using var builder = new NestedKeyTemplateBuilder();

        using ObjectTemplate template = builder
            .Class(CKO.CKO_SECRET_KEY)
            .KeyType(CKK.CKK_AES)
            .Sensitive()
            .NonExtractable()
            .WrapWithTrusted()
            .ValueLen(32)
            .Build();

        ulong[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains((ulong)CKA.CKA_CLASS, present);
        Assert.Contains((ulong)CKA.CKA_KEY_TYPE, present);
        Assert.Contains((ulong)CKA.CKA_SENSITIVE, present);
        Assert.Contains((ulong)CKA.CKA_EXTRACTABLE, present);
        Assert.Contains((ulong)CKA.CKA_WRAP_WITH_TRUSTED, present);
        Assert.Contains((ulong)CKA.CKA_VALUE_LEN, present);
    }

    [Fact]
    public void Extractable_And_NonExtractable_SetOppositeValues()
    {
        using var extractable = new NestedKeyTemplateBuilder();
        using ObjectTemplate yes = extractable.Extractable().Build();
        Assert.True(yes.Attributes.Single(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE).GetValueAsBool());

        using var nonExtractable = new NestedKeyTemplateBuilder();
        using ObjectTemplate no = nonExtractable.NonExtractable().Build();
        Assert.False(no.Attributes.Single(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE).GetValueAsBool());
    }
}
