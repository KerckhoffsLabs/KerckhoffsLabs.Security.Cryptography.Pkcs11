using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for an asymmetric private-key template. Defaults to
/// <c>CKA_PRIVATE = true</c>, <c>CKA_SENSITIVE = true</c>, and
/// <c>CKA_EXTRACTABLE = false</c>; callers can opt out explicitly.
/// </summary>
public sealed class PrivateKeyTemplateBuilder : ObjectTemplateBuilderBase<PrivateKeyTemplateBuilder>
{
    internal PrivateKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
        Set(new ObjectAttribute(CKA.CKA_PRIVATE, true));
        Set(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        Set(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
    }

    /// <summary>Sets <c>CKA_SENSITIVE</c>.</summary>
    public PrivateKeyTemplateBuilder Sensitive(bool value = true) => Attribute(CKA.CKA_SENSITIVE, value);

    /// <summary>Reinforces the non-extractable default.</summary>
    public PrivateKeyTemplateBuilder NonExtractable() => Attribute(CKA.CKA_EXTRACTABLE, false);

    /// <summary>Marks the key as extractable — insecure; callers must explicitly opt in.</summary>
    public PrivateKeyTemplateBuilder Extractable() => Attribute(CKA.CKA_EXTRACTABLE, true);

    /// <summary>Sets <c>CKA_SIGN</c>.</summary>
    public PrivateKeyTemplateBuilder Sign(bool value = true) => Attribute(CKA.CKA_SIGN, value);

    /// <summary>Sets <c>CKA_SIGN_RECOVER</c>.</summary>
    public PrivateKeyTemplateBuilder SignRecover(bool value = true) => Attribute(CKA.CKA_SIGN_RECOVER, value);

    /// <summary>Sets <c>CKA_DECRYPT</c>.</summary>
    public PrivateKeyTemplateBuilder Decrypt(bool value = true) => Attribute(CKA.CKA_DECRYPT, value);

    /// <summary>Sets <c>CKA_UNWRAP</c>.</summary>
    public PrivateKeyTemplateBuilder Unwrap(bool value = true) => Attribute(CKA.CKA_UNWRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public PrivateKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);
}
