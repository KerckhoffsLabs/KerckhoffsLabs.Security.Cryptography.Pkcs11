using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for a secret (symmetric) key template. Defaults to the secure
/// posture of <c>CKA_SENSITIVE = true</c> and <c>CKA_EXTRACTABLE = false</c>; callers can
/// opt out explicitly via <see cref="Sensitive(bool)"/> / <see cref="Extractable"/>.
/// </summary>
/// <remarks>
/// Every capability attribute (<c>CKA_ENCRYPT</c>, <c>CKA_DECRYPT</c>, <c>CKA_SIGN</c>,
/// <c>CKA_VERIFY</c>, <c>CKA_WRAP</c>, <c>CKA_UNWRAP</c>, <c>CKA_DERIVE</c>) also defaults to
/// <c>false</c>. PKCS#11's own spec default for an omitted capability attribute is <c>CK_TRUE</c>
/// (verified against NSS and SoftHSM) — an omission-means-safe assumption would silently grant
/// every role on every key this builder produces. Callers opt in to each role explicitly.
/// </remarks>
public sealed class SecretKeyTemplateBuilder : ObjectTemplateBuilderBase<SecretKeyTemplateBuilder>
{
    internal SecretKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
        // Secure defaults — see spec section "Security properties preserved".
        Set(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        Set(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
        // PKCS#11 defaults an omitted capability attribute to CK_TRUE, not CK_FALSE — refuse every
        // role by default so a caller who forgets to ask for one doesn't silently get it anyway.
        Set(new ObjectAttribute(CKA.CKA_ENCRYPT, false));
        Set(new ObjectAttribute(CKA.CKA_DECRYPT, false));
        Set(new ObjectAttribute(CKA.CKA_SIGN, false));
        Set(new ObjectAttribute(CKA.CKA_VERIFY, false));
        Set(new ObjectAttribute(CKA.CKA_WRAP, false));
        Set(new ObjectAttribute(CKA.CKA_UNWRAP, false));
        Set(new ObjectAttribute(CKA.CKA_DERIVE, false));
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

    /// <summary>
    /// Sets <c>CKA_WRAP_WITH_TRUSTED</c> — this key can only be wrapped by a wrapping key that
    /// itself carries <c>CKA_TRUSTED</c>. Defence in depth for a key deliberately made wrappable.
    /// </summary>
    public SecretKeyTemplateBuilder WrapWithTrusted(bool value = true)
        => Attribute(CKA.CKA_WRAP_WITH_TRUSTED, value);

    /// <summary>
    /// Sets <c>CKA_TRUSTED</c> — marks this key as an approved wrapping key for keys that carry
    /// <c>CKA_WRAP_WITH_TRUSTED</c>.
    /// </summary>
    /// <remarks>
    /// Per PKCS#11, <c>CKA_TRUSTED</c> may be set to true <b>only by the SO</b>. A template that
    /// sets it from a normal user session is rejected by a conformant token with
    /// <see cref="CKR.CKR_ATTRIBUTE_READ_ONLY"/>. This is not gated locally: the builder cannot
    /// know which user type opened the session, and refusing at build time would be wrong for SO
    /// sessions.
    /// </remarks>
    public SecretKeyTemplateBuilder Trusted(bool value = true)
        => Attribute(CKA.CKA_TRUSTED, value);

    /// <summary>
    /// Sets <c>CKA_WRAP_TEMPLATE</c> — the template a key must <b>match</b> to be wrapped by this
    /// key. Keys that do not match cannot be wrapped, so this narrows what this key can exfiltrate.
    /// Contrast <see cref="UnwrapTemplate"/>, which imposes attributes rather than matching them.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="configure"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public SecretKeyTemplateBuilder WrapTemplate(Action<NestedKeyTemplateBuilder> configure)
        => NestedTemplate(CKA.CKA_WRAP_TEMPLATE, configure);

    /// <summary>
    /// Sets <c>CKA_UNWRAP_TEMPLATE</c> — attributes <b>imposed</b> on every key unwrapped with this
    /// key. The token applies them as if the object already carried them, before any caller-supplied
    /// template. Contrast <see cref="WrapTemplate"/>, which matches rather than imposes.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="configure"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public SecretKeyTemplateBuilder UnwrapTemplate(Action<NestedKeyTemplateBuilder> configure)
        => NestedTemplate(CKA.CKA_UNWRAP_TEMPLATE, configure);

    /// <summary>
    /// Sets <c>CKA_DERIVE_TEMPLATE</c> — attributes <b>imposed</b> on every key derived from this key.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="configure"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public SecretKeyTemplateBuilder DeriveTemplate(Action<NestedKeyTemplateBuilder> configure)
        => NestedTemplate(CKA.CKA_DERIVE_TEMPLATE, configure);
}
