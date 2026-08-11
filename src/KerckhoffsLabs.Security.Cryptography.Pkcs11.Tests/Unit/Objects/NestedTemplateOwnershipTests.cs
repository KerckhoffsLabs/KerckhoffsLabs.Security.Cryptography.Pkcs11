using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// The nested attribute array holds flat copies of its children's CK_ATTRIBUTE structs, pointers
/// included. These tests pin the ownership chain that keeps those pointers valid: the builder owns
/// the children until Build, the produced template owns them afterwards, and nothing the caller
/// does in between can strand them.
/// </summary>
public sealed class NestedTemplateOwnershipTests
{
    [Fact]
    public void WrapTemplate_MarshalsTheNestedChildren()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).Sensitive())
            .Build();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
        ObjectAttribute[] children = parent.GetValueAsAttributeArray();

        // Only Type is safe to read: each child wraps a fresh CK_ATTRIBUTE pointing at the same
        // unmanaged buffer the parent owns.
        Assert.Equal(2, children.Length);
        Assert.Contains((ulong)CKA.CKA_CLASS, children.Select(c => c.Type));
        Assert.Contains((ulong)CKA.CKA_SENSITIVE, children.Select(c => c.Type));
    }

    /// <summary>
    /// Smoke test only: the read path still works after the builder that produced the template is
    /// disposed. It does NOT prove ownership transferred - <c>GetValueAsAttributeArray</c> reads only
    /// the parent's own flat buffer and never dereferences the children's <c>pValue</c> pointers, so
    /// this would pass even if the builder still owned (and could free) the nested children.
    /// <see cref="Build_TransfersOwnershipOfNestedChildren"/> is what actually pins the transfer.
    /// </summary>
    [Fact]
    public void NestedChildren_SurviveDisposingTheBuilderAfterBuild()
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY));
        using ObjectTemplate template = builder.Build();

        builder.Dispose();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
        Assert.Single(parent.GetValueAsAttributeArray());
    }

    /// <summary>
    /// Ownership must transfer at Build rather than be shared. Both halves are asserted, because
    /// each alone is satisfiable by a broken implementation: the builder letting go proves nothing
    /// if nobody catches, and a template holding children proves nothing if the builder also kept
    /// them. Dropping the nested list from the <c>ObjectTemplate</c> the builder returns leaves
    /// the children unreferenced, so a later GC finalizes them and frees the buffers the parent's
    /// flat <c>CK_ATTRIBUTE</c> copy still points at, mid token call.
    /// </summary>
    [Fact]
    public void Build_TransfersOwnershipOfNestedChildren()
    {
        using var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES);
        builder.WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY));

        Assert.Single(builder.NestedTemplates);

        using ObjectTemplate template = builder.Build();

        Assert.Empty(builder.NestedTemplates);      // the builder let go...
        Assert.Single(template.NestedChildren);     // ...and the template caught
    }

    /// <summary>
    /// Setting the same nested attribute twice must release the displaced child, not orphan it.
    /// The displaced parent attribute is freed by <c>Set</c>; its children are this builder's to
    /// release.
    /// </summary>
    [Fact]
    public void WrapTemplate_CalledTwice_DisposesTheDisplacedChild()
    {
        using var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES);
        builder.WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY));

        ObjectAttribute displaced = builder.NestedTemplates.Single().Attributes.Single();

        builder.WrapTemplate(t => t.Sensitive());

        Assert.Throws<ObjectDisposedException>(() => displaced.GetValueAsUlong());
    }

    [Fact]
    public void WrapTemplate_CalledTwice_KeepsOnlyTheLast()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY))
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).Sensitive().NonExtractable())
            .Build();

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
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

        ObjectAttribute parent = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
        Assert.Equal(2, parent.GetValueAsAttributeArray().Length);
        Assert.Single(template.NestedChildren);
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

        ulong[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains((ulong)CKA.CKA_UNWRAP_TEMPLATE, present);
        Assert.Contains((ulong)CKA.CKA_DERIVE_TEMPLATE, present);
    }

    [Fact]
    public void PrivateKey_SupportsUnwrapAndDeriveTemplates()
    {
        using ObjectTemplate template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .UnwrapTemplate(t => t.Sensitive().NonExtractable())
            .DeriveTemplate(t => t.Sensitive())
            .Build();

        ulong[] present = [.. template.Attributes.Select(a => a.Type)];
        Assert.Contains((ulong)CKA.CKA_UNWRAP_TEMPLATE, present);
        Assert.Contains((ulong)CKA.CKA_DERIVE_TEMPLATE, present);
    }

    [Fact]
    public void PublicKey_SupportsWrapTemplate()
    {
        using ObjectTemplate template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY).NonExtractable())
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
    }

    /// <summary>
    /// Two different nested templates on one builder are independent - setting the second must not
    /// disturb the first, which the shared _nested dictionary keyed by CKA is what guarantees.
    /// </summary>
    [Fact]
    public void TwoDifferentNestedTemplates_AreIndependent()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapTemplate(t => t.Class(CKO.CKO_SECRET_KEY))
            .UnwrapTemplate(t => t.Sensitive().NonExtractable().Class(CKO.CKO_SECRET_KEY))
            .Build();

        ObjectAttribute wrap = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_TEMPLATE);
        ObjectAttribute unwrap = template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_UNWRAP_TEMPLATE);

        Assert.Single(wrap.GetValueAsAttributeArray());
        Assert.Equal(3, unwrap.GetValueAsAttributeArray().Length);
    }
}
