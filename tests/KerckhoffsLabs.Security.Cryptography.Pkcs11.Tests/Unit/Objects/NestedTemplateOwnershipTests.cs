using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
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
    // Every member array and value, at every level, lies inside the parent's single block: a block
    // sized too small would have the copy run past its end.
    [Fact]
    public void NestedArray_EveryLevelLiesInsideTheParentsBlock()
    {
        using var label = new ObjectAttribute(CKA.CKA_LABEL, "a label longer than one pointer");
        using var id = new ObjectAttribute(CKA.CKA_ID, [1, 2, 3]);
        using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var deepest = new ObjectAttribute(CKA.CKA_DERIVE_TEMPLATE, [label, id]);
        using var middle = new ObjectAttribute(CKA.CKA_UNWRAP_TEMPLATE, [deepest, sensitive]);
        using var outer = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [middle]);

        CK_ATTRIBUTE root = outer.CkAttribute;
        Assert.True(LiveAllocations.TryFind(root.value, out IntPtr start, out int size));
        Assert.Equal(root.value, start);

        int checkedValues = AssertInside(root, start, size);

        Assert.Equal(6, checkedValues); // 3 arrays and 3 values
        ObjectAttribute deep = outer.GetValueAsAttributeArray().Single().GetValueAsAttributeArray()[0];
        Assert.Equal("a label longer than one pointer", deep.GetValueAsAttributeArray()[0].GetValueAsString());
    }

    private static int AssertInside(CK_ATTRIBUTE attribute, IntPtr start, int size)
    {
        int length = (int)(ulong)attribute.valueLen;
        long offset = attribute.value.ToInt64() - start.ToInt64();
        Assert.InRange(offset, 0, size - length);
        int count = 1;
        if ((CKA)(ulong)attribute.type is CKA.CKA_WRAP_TEMPLATE or CKA.CKA_UNWRAP_TEMPLATE or CKA.CKA_DERIVE_TEMPLATE)
        {
            int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
            for (int i = 0; i < length / stride; i++)
                count += AssertInside(UnmanagedMemory.Read<CK_ATTRIBUTE>(IntPtr.Add(attribute.value, i * stride)), start, size);
        }
        return count;
    }

    // Four levels of arrays below the outermost are allowed; a fifth is refused.
    [Fact]
    public void NestingDeeperThanFourLevels_IsRefused()
    {
        using var leaf = new ObjectAttribute(CKA.CKA_LABEL, "leaf");
        using var level1 = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [leaf]);
        using var level2 = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [level1]);
        using var level3 = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [level2]);
        using var level4 = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [level3]);
        using var level5 = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [level4]);

        var ex = Assert.Throws<ArgumentException>(() => new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [level5]));
        Assert.StartsWith("Attribute arrays nested more than 4 deep.", ex.Message, StringComparison.Ordinal);
    }

    // A member that carries no value (unavailable, or a length with no buffer, as a size query
    // leaves it) is copied without its pointer, which is never followed.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MemberWithoutAValue_IsCopiedWithoutItsPointer(bool unavailable)
    {
        var raw = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_VALUE,
            value = unavailable ? new IntPtr(0x10) : IntPtr.Zero, // never dereferenced
            valueLen = unavailable ? NativeCULong.MaxValue : (NativeCULong)16UL,
        };
        using var member = new ObjectAttribute(raw, ownsValue: false);

        using var parent = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [member]);

        CK_ATTRIBUTE copied = parent.GetValueAsAttributeArray().Single().CkAttribute;
        Assert.Equal(IntPtr.Zero, copied.value);
        Assert.Equal(raw.valueLen, copied.valueLen);
    }
}
