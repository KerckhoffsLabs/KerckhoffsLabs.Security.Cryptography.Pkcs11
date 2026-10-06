using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// A nested attribute array (<c>CKA_WRAP_TEMPLATE</c> and friends) owns one block holding its
/// members and their values. These tests pin that it never points at memory owned by anyone else:
/// the children it was built from can go away, and the builder can be disposed, without touching it.
/// </summary>
public sealed class NestedTemplateOwnershipTests
{
    [Fact]
    public void WrapTemplate_MarshalsTheNestedChildren()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).Sensitive())
            .Build();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == CKA.CKA_WRAP_TEMPLATE);
        ObjectAttribute[] children = parent.GetValueAsAttributeArray();

        // The values are inside the parent's own block, so they are readable after the builder and
        // its child template are long gone.
        Assert.Equal(2, children.Length);
        Assert.Equal((ulong)CKO.CKO_SECRET_KEY, children.Single(c => c.Type == CKA.CKA_CLASS).GetValueAsUlong());
        Assert.True(children.Single(c => c.Type == CKA.CKA_SENSITIVE).GetValueAsBool());
    }

    /// <summary>
    /// The public constructor used to copy the children's <c>CK_ATTRIBUTE</c> structs, pointers
    /// included, without keeping the children: once they were disposed or collected, the parent
    /// pointed at freed memory, and a token reading the template read it.
    /// </summary>
    [Fact]
    public void Constructor_CopiesTheChildrenValues_SoTheChildrenCanBeDisposed()
    {
        var label = new ObjectAttribute(CKA.CKA_LABEL, "wrapped");
        var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var parent = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [label, cls]);

        label.Dispose();
        cls.Dispose();

        ObjectAttribute[] members = parent.GetValueAsAttributeArray();
        Assert.Equal("wrapped", members[0].GetValueAsString());
        Assert.Equal((ulong)CKO.CKO_SECRET_KEY, members[1].GetValueAsUlong());
    }

    [Fact]
    public void Constructor_RefusesADisposedChild()
    {
        var child = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        child.Dispose();

        Assert.Throws<ObjectDisposedException>(() => new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [child]));
    }

    [Fact]
    public void Constructor_CopiesANestedArrayMember_Recursively()
    {
        using var inner = new ObjectAttribute(CKA.CKA_DERIVE_TEMPLATE, [new ObjectAttribute(CKA.CKA_LABEL, "deep")]);
        using var outer = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [inner]);

        ObjectAttribute member = outer.GetValueAsAttributeArray().Single();
        Assert.Equal("deep", member.GetValueAsAttributeArray().Single().GetValueAsString());
    }

    [Fact]
    public void NestedChildren_SurviveDisposingTheBuilderAfterBuild()
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY));
        using ObjectTemplate template = builder.Build();

        builder.Dispose();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == CKA.CKA_WRAP_TEMPLATE);
        Assert.Equal((ulong)CKO.CKO_SECRET_KEY, parent.GetValueAsAttributeArray().Single().GetValueAsUlong());
    }

    [Fact]
    public void WrapTemplate_CalledTwice_KeepsOnlyTheLast()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY))
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).Sensitive().NonExtractable())
            .Build();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == CKA.CKA_WRAP_TEMPLATE);
        Assert.Equal(3, parent.GetValueAsAttributeArray().Length);
    }

    /// <summary>
    /// The vendor-defined-CKO builder has no typed wrap/unwrap helpers, so without the generic
    /// <c>Attribute(CKA, Action&lt;…&gt;)</c> overload nested templates stay unreachable there —
    /// the same gap this work exists to close, just moved to a different builder.
    /// </summary>
    [Fact]
    public void GenericBuilder_ReachesNestedTemplates_ThroughTheAttributeEscapeHatch()
    {
        using ObjectTemplate template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_SECRET_KEY)
            .Attribute(CKA.CKA_WRAP_TEMPLATE, t => t.Sensitive().NonExtractable())
            .Build();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == CKA.CKA_WRAP_TEMPLATE);
        Assert.Equal(2, parent.GetValueAsAttributeArray().Length);
    }

    [Fact]
    public void WrapTemplate_NullCallback_Throws()
    {
        using var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES);

        Assert.Throws<ArgumentNullException>(() => builder.WrapTemplate(null!));
    }

    [Fact]
    public void WrapTemplate_AfterBuild_Throws()
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES);
        using ObjectTemplate template = builder.Build();

        Assert.Throws<InvalidOperationException>(() => builder.WrapTemplate(t => t.Sensitive()));
    }

    [Fact]
    public void WrapTemplate_AfterDispose_Throws()
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES);
        builder.Dispose();

        Assert.Throws<ObjectDisposedException>(() => builder.WrapTemplate(t => t.Sensitive()));
    }

    [Fact]
    public void SecretKey_SupportsUnwrapAndDeriveTemplates()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .UnwrapTemplate(t => t.Sensitive().NonExtractable())
            .DeriveTemplate(t => t.Sensitive())
            .Build();

        CKA[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains(CKA.CKA_UNWRAP_TEMPLATE, present);
        Assert.Contains(CKA.CKA_DERIVE_TEMPLATE, present);
    }

    [Fact]
    public void PrivateKey_SupportsUnwrapAndDeriveTemplates()
    {
        using ObjectTemplate template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .UnwrapTemplate(t => t.Sensitive().NonExtractable())
            .DeriveTemplate(t => t.Sensitive())
            .Build();

        CKA[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains(CKA.CKA_UNWRAP_TEMPLATE, present);
        Assert.Contains(CKA.CKA_DERIVE_TEMPLATE, present);
    }

    [Fact]
    public void PublicKey_SupportsWrapTemplate()
    {
        using ObjectTemplate template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).NonExtractable())
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == CKA.CKA_WRAP_TEMPLATE);
    }

    /// <summary>
    /// Two different nested templates on one builder are independent: setting the second must not
    /// disturb the first.
    /// </summary>
    [Fact]
    public void TwoDifferentNestedTemplates_AreIndependent()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY))
            .UnwrapTemplate(t => t.Sensitive().NonExtractable().Class(CKO.CKO_SECRET_KEY))
            .Build();

        ObjectAttribute wrap = template.Attributes.Single(a => a.Type == CKA.CKA_WRAP_TEMPLATE);
        ObjectAttribute unwrap = template.Attributes.Single(a => a.Type == CKA.CKA_UNWRAP_TEMPLATE);

        Assert.Single(wrap.GetValueAsAttributeArray());
        Assert.Equal(3, unwrap.GetValueAsAttributeArray().Length);
    }
}
