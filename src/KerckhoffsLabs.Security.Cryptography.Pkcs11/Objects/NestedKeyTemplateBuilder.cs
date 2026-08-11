using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for a template nested inside another key's <c>CKA_WRAP_TEMPLATE</c>,
/// <c>CKA_UNWRAP_TEMPLATE</c> or <c>CKA_DERIVE_TEMPLATE</c>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the top-level key builders, this one applies <b>no secure defaults</b>. The same nested
/// template means opposite things depending on which attribute carries it, and a silent default
/// would be wrong in one of the two directions:
/// </para>
/// <list type="bullet">
/// <item><description>
/// In <c>CKA_WRAP_TEMPLATE</c> it is a <b>filter</b> — keys that do not match cannot be wrapped by
/// this key. An injected <c>CKA_SENSITIVE</c> would narrow which keys are wrappable in a way the
/// caller never wrote.
/// </description></item>
/// <item><description>
/// In <c>CKA_UNWRAP_TEMPLATE</c> and <c>CKA_DERIVE_TEMPLATE</c> it is an <b>imposition</b> — the
/// attributes forced onto the key the operation produces.
/// </description></item>
/// </list>
/// <para>
/// Instances are created and owned by the outer builder's template helpers; callers receive one
/// only as the argument to a configuration callback and never need to dispose it.
/// </para>
/// </remarks>
public sealed class NestedKeyTemplateBuilder : ObjectTemplateBuilderBase<NestedKeyTemplateBuilder>
{
    internal NestedKeyTemplateBuilder() { }

    /// <summary>Sets <c>CKA_CLASS</c>.</summary>
    public NestedKeyTemplateBuilder Class(CKO value) => Attribute(CKA.CKA_CLASS, (ulong)value);

    /// <summary>Sets <c>CKA_KEY_TYPE</c>.</summary>
    public NestedKeyTemplateBuilder KeyType(CKK value) => Attribute(CKA.CKA_KEY_TYPE, (ulong)value);

    /// <summary>Sets <c>CKA_SENSITIVE</c>.</summary>
    public NestedKeyTemplateBuilder Sensitive(bool value = true) => Attribute(CKA.CKA_SENSITIVE, value);

    /// <summary>Sets <c>CKA_EXTRACTABLE = true</c>.</summary>
    public NestedKeyTemplateBuilder Extractable() => Attribute(CKA.CKA_EXTRACTABLE, true);

    /// <summary>Sets <c>CKA_EXTRACTABLE = false</c>.</summary>
    public NestedKeyTemplateBuilder NonExtractable() => Attribute(CKA.CKA_EXTRACTABLE, false);

    /// <summary>Sets <c>CKA_WRAP_WITH_TRUSTED</c>.</summary>
    public NestedKeyTemplateBuilder WrapWithTrusted(bool value = true)
        => Attribute(CKA.CKA_WRAP_WITH_TRUSTED, value);

    /// <summary>Sets <c>CKA_PRIVATE</c>.</summary>
    public NestedKeyTemplateBuilder Private(bool value = true) => Attribute(CKA.CKA_PRIVATE, value);

    /// <summary>Sets <c>CKA_MODIFIABLE</c>.</summary>
    public NestedKeyTemplateBuilder Modifiable(bool value = true) => Attribute(CKA.CKA_MODIFIABLE, value);

    /// <summary>Sets <c>CKA_ENCRYPT</c>.</summary>
    public NestedKeyTemplateBuilder Encrypt(bool value = true) => Attribute(CKA.CKA_ENCRYPT, value);

    /// <summary>Sets <c>CKA_DECRYPT</c>.</summary>
    public NestedKeyTemplateBuilder Decrypt(bool value = true) => Attribute(CKA.CKA_DECRYPT, value);

    /// <summary>Sets <c>CKA_SIGN</c>.</summary>
    public NestedKeyTemplateBuilder Sign(bool value = true) => Attribute(CKA.CKA_SIGN, value);

    /// <summary>Sets <c>CKA_VERIFY</c>.</summary>
    public NestedKeyTemplateBuilder Verify(bool value = true) => Attribute(CKA.CKA_VERIFY, value);

    /// <summary>Sets <c>CKA_WRAP</c>.</summary>
    public NestedKeyTemplateBuilder Wrap(bool value = true) => Attribute(CKA.CKA_WRAP, value);

    /// <summary>Sets <c>CKA_UNWRAP</c>.</summary>
    public NestedKeyTemplateBuilder Unwrap(bool value = true) => Attribute(CKA.CKA_UNWRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public NestedKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);

    /// <summary>Sets <c>CKA_VALUE_LEN</c> — the key length in bytes.</summary>
    public NestedKeyTemplateBuilder ValueLen(int bytes) => Attribute(CKA.CKA_VALUE_LEN, (ulong)bytes);
}
