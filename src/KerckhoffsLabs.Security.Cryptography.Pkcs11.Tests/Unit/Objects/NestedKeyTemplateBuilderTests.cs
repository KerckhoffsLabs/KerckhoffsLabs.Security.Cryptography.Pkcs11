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

        CKA[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains(CKA.CKA_CLASS, present);
        Assert.Contains(CKA.CKA_KEY_TYPE, present);
        Assert.Contains(CKA.CKA_SENSITIVE, present);
        Assert.Contains(CKA.CKA_EXTRACTABLE, present);
        Assert.Contains(CKA.CKA_WRAP_WITH_TRUSTED, present);
        Assert.Contains(CKA.CKA_VALUE_LEN, present);
    }

    [Fact]
    public void Extractable_And_NonExtractable_SetOppositeValues()
    {
        using var extractable = new NestedKeyTemplateBuilder();
        using ObjectTemplate yes = extractable.Extractable().Build();
        Assert.True(yes.Attributes.Single(a => a.Type == CKA.CKA_EXTRACTABLE).GetValueAsBool());

        using var nonExtractable = new NestedKeyTemplateBuilder();
        using ObjectTemplate no = nonExtractable.NonExtractable().Build();
        Assert.False(no.Attributes.Single(a => a.Type == CKA.CKA_EXTRACTABLE).GetValueAsBool());
    }

    [Fact]
    public void Helpers_EncodeTheValuesTheyWereGiven()
    {
        using var builder = new NestedKeyTemplateBuilder();

        using ObjectTemplate template = builder
            .Class(CKO.CKO_SECRET_KEY)
            .KeyType(CKK.CKK_AES)
            .ValueLen(32)
            .Build();

        Assert.Equal((ulong)CKO.CKO_SECRET_KEY, Single(template, CKA.CKA_CLASS).GetValueAsUlong());
        Assert.Equal((ulong)CKK.CKK_AES, Single(template, CKA.CKA_KEY_TYPE).GetValueAsUlong());
        Assert.Equal(32UL, Single(template, CKA.CKA_VALUE_LEN).GetValueAsUlong());
    }

    public static TheoryData<string, CKA> BooleanSetters() => new()
    {
        { nameof(NestedKeyTemplateBuilder.Sensitive), CKA.CKA_SENSITIVE },
        { nameof(NestedKeyTemplateBuilder.WrapWithTrusted), CKA.CKA_WRAP_WITH_TRUSTED },
        { nameof(NestedKeyTemplateBuilder.Private), CKA.CKA_PRIVATE },
        { nameof(NestedKeyTemplateBuilder.Modifiable), CKA.CKA_MODIFIABLE },
        { nameof(NestedKeyTemplateBuilder.Encrypt), CKA.CKA_ENCRYPT },
        { nameof(NestedKeyTemplateBuilder.Decrypt), CKA.CKA_DECRYPT },
        { nameof(NestedKeyTemplateBuilder.Sign), CKA.CKA_SIGN },
        { nameof(NestedKeyTemplateBuilder.Verify), CKA.CKA_VERIFY },
        { nameof(NestedKeyTemplateBuilder.Wrap), CKA.CKA_WRAP },
        { nameof(NestedKeyTemplateBuilder.Unwrap), CKA.CKA_UNWRAP },
        { nameof(NestedKeyTemplateBuilder.Derive), CKA.CKA_DERIVE },
    };

    /// <summary>
    /// Each boolean setter defaults to <c>true</c> and honours an explicit <c>false</c> - which
    /// matters in a <c>CKA_UNWRAP_TEMPLATE</c>, where <c>false</c> is the restriction being imposed.
    /// </summary>
    [Theory]
    [MemberData(nameof(BooleanSetters))]
    public void BooleanSetter_DefaultsToTrue_AndHonoursFalse(string setter, CKA expected)
    {
        using var defaulted = new NestedKeyTemplateBuilder();
        using ObjectTemplate yes = Apply(defaulted, setter, value: null).Build();
        Assert.Equal(1, yes.Count);
        Assert.True(Single(yes, expected).GetValueAsBool());

        using var explicitFalse = new NestedKeyTemplateBuilder();
        using ObjectTemplate no = Apply(explicitFalse, setter, value: false).Build();
        Assert.Equal(1, no.Count);
        Assert.False(Single(no, expected).GetValueAsBool());
    }

    private static NestedKeyTemplateBuilder Apply(NestedKeyTemplateBuilder b, string setter, bool? value) => setter switch
    {
        nameof(NestedKeyTemplateBuilder.Sensitive) => value is { } v ? b.Sensitive(v) : b.Sensitive(),
        nameof(NestedKeyTemplateBuilder.WrapWithTrusted) => value is { } v ? b.WrapWithTrusted(v) : b.WrapWithTrusted(),
        nameof(NestedKeyTemplateBuilder.Private) => value is { } v ? b.Private(v) : b.Private(),
        nameof(NestedKeyTemplateBuilder.Modifiable) => value is { } v ? b.Modifiable(v) : b.Modifiable(),
        nameof(NestedKeyTemplateBuilder.Encrypt) => value is { } v ? b.Encrypt(v) : b.Encrypt(),
        nameof(NestedKeyTemplateBuilder.Decrypt) => value is { } v ? b.Decrypt(v) : b.Decrypt(),
        nameof(NestedKeyTemplateBuilder.Sign) => value is { } v ? b.Sign(v) : b.Sign(),
        nameof(NestedKeyTemplateBuilder.Verify) => value is { } v ? b.Verify(v) : b.Verify(),
        nameof(NestedKeyTemplateBuilder.Wrap) => value is { } v ? b.Wrap(v) : b.Wrap(),
        nameof(NestedKeyTemplateBuilder.Unwrap) => value is { } v ? b.Unwrap(v) : b.Unwrap(),
        nameof(NestedKeyTemplateBuilder.Derive) => value is { } v ? b.Derive(v) : b.Derive(),
        _ => throw new ArgumentOutOfRangeException(nameof(setter), setter, null),
    };

    private static ObjectAttribute Single(ObjectTemplate template, CKA type)
        => template.Attributes.Single(a => a.Type == type);
}
