using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for a secret (symmetric) key template. Defaults to the secure
/// posture of <c>CKA_SENSITIVE = true</c> and <c>CKA_EXTRACTABLE = false</c>; callers can
/// opt out explicitly via <see cref="Sensitive(bool)"/> / <see cref="Extractable"/>.
/// </summary>
public sealed class SecretKeyTemplateBuilder : ObjectTemplateBuilderBase<SecretKeyTemplateBuilder>
{
    internal SecretKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
        // Secure defaults — see spec section "Security properties preserved".
        Set(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        Set(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
    }

    /// <summary>Sets <c>CKA_SENSITIVE</c>. Defaults to <c>true</c> on construction.</summary>
    public SecretKeyTemplateBuilder Sensitive(bool value = true)
        => Attribute(CKA.CKA_SENSITIVE, value);

    /// <summary>Sets <c>CKA_EXTRACTABLE = false</c>. Redundant when used right after the
    /// builder ctor, but clarifies intent at the call site.</summary>
    public SecretKeyTemplateBuilder NonExtractable()
        => Attribute(CKA.CKA_EXTRACTABLE, false);

    /// <summary>Sets <c>CKA_EXTRACTABLE = true</c>. Insecure-by-PKCS#11-standard;
    /// callers must explicitly opt in.</summary>
    public SecretKeyTemplateBuilder Extractable()
        => Attribute(CKA.CKA_EXTRACTABLE, true);

    /// <summary>Sets <c>CKA_VALUE_LEN</c> — the key length in bytes (used by
    /// <c>C_GenerateKey</c>).</summary>
    public SecretKeyTemplateBuilder ValueLen(int bytes)
        => Attribute(CKA.CKA_VALUE_LEN, (ulong)bytes);

    /// <summary>Sets <c>CKA_VALUE</c> — the literal key bytes (used by
    /// <c>C_CreateObject</c> when importing key material).</summary>
    public SecretKeyTemplateBuilder Value(ReadOnlySpan<byte> value)
        => Attribute(CKA.CKA_VALUE, value);

    /// <summary>Sets <c>CKA_ENCRYPT</c>.</summary>
    public SecretKeyTemplateBuilder Encrypt(bool value = true) => Attribute(CKA.CKA_ENCRYPT, value);

    /// <summary>Sets <c>CKA_DECRYPT</c>.</summary>
    public SecretKeyTemplateBuilder Decrypt(bool value = true) => Attribute(CKA.CKA_DECRYPT, value);

    /// <summary>Sets <c>CKA_SIGN</c>.</summary>
    public SecretKeyTemplateBuilder Sign(bool value = true) => Attribute(CKA.CKA_SIGN, value);

    /// <summary>Sets <c>CKA_VERIFY</c>.</summary>
    public SecretKeyTemplateBuilder Verify(bool value = true) => Attribute(CKA.CKA_VERIFY, value);

    /// <summary>Sets <c>CKA_WRAP</c>.</summary>
    public SecretKeyTemplateBuilder Wrap(bool value = true) => Attribute(CKA.CKA_WRAP, value);

    /// <summary>Sets <c>CKA_UNWRAP</c>.</summary>
    public SecretKeyTemplateBuilder Unwrap(bool value = true) => Attribute(CKA.CKA_UNWRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public SecretKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);
}
