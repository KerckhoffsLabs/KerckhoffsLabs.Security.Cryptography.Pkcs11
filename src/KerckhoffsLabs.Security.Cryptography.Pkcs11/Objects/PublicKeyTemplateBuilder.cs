using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for an asymmetric public-key template. Public keys are not sensitive
/// material; no secure-default sensitivity attributes are pre-set.
/// </summary>
public sealed class PublicKeyTemplateBuilder : ObjectTemplateBuilderBase<PublicKeyTemplateBuilder>
{
    internal PublicKeyTemplateBuilder(CKK keyType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
        Set(new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType));
    }

    /// <summary>Sets <c>CKA_VERIFY</c>.</summary>
    public PublicKeyTemplateBuilder Verify(bool value = true) => Attribute(CKA.CKA_VERIFY, value);

    /// <summary>Sets <c>CKA_VERIFY_RECOVER</c>.</summary>
    public PublicKeyTemplateBuilder VerifyRecover(bool value = true) => Attribute(CKA.CKA_VERIFY_RECOVER, value);

    /// <summary>Sets <c>CKA_ENCRYPT</c>.</summary>
    public PublicKeyTemplateBuilder Encrypt(bool value = true) => Attribute(CKA.CKA_ENCRYPT, value);

    /// <summary>Sets <c>CKA_WRAP</c>.</summary>
    public PublicKeyTemplateBuilder Wrap(bool value = true) => Attribute(CKA.CKA_WRAP, value);

    /// <summary>Sets <c>CKA_DERIVE</c>.</summary>
    public PublicKeyTemplateBuilder Derive(bool value = true) => Attribute(CKA.CKA_DERIVE, value);

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
    public PublicKeyTemplateBuilder Trusted(bool value = true)
        => Attribute(CKA.CKA_TRUSTED, value);

    /// <summary>Sets <c>CKA_MODULUS_BITS</c> — RSA modulus length (used by
    /// <c>C_GenerateKeyPair</c>).</summary>
    public PublicKeyTemplateBuilder ModulusBits(int bits) => Attribute(CKA.CKA_MODULUS_BITS, (ulong)bits);

    /// <summary>Sets <c>CKA_PUBLIC_EXPONENT</c> — RSA public exponent.</summary>
    public PublicKeyTemplateBuilder PublicExponent(ReadOnlySpan<byte> exponent)
        => Attribute(CKA.CKA_PUBLIC_EXPONENT, exponent);

    /// <summary>Sets <c>CKA_EC_PARAMS</c> — EC curve parameters (DER-encoded).</summary>
    public PublicKeyTemplateBuilder EcParams(ReadOnlySpan<byte> derParams)
        => Attribute(CKA.CKA_EC_PARAMS, derParams);

    /// <summary>
    /// Sets <c>CKA_WRAP_TEMPLATE</c> — the template a key must <b>match</b> to be wrapped by this
    /// key. Keys that do not match cannot be wrapped, so this narrows what this key can exfiltrate.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="configure"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public PublicKeyTemplateBuilder WrapTemplate(Action<NestedKeyTemplateBuilder> configure)
        => NestedTemplate(CKA.CKA_WRAP_TEMPLATE, configure);
}
