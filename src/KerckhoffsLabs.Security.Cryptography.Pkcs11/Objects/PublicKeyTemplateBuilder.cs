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

    /// <summary>Sets <c>CKA_MODULUS_BITS</c> — RSA modulus length (used by
    /// <c>C_GenerateKeyPair</c>).</summary>
    public PublicKeyTemplateBuilder ModulusBits(int bits) => Attribute(CKA.CKA_MODULUS_BITS, (ulong)bits);

    /// <summary>Sets <c>CKA_PUBLIC_EXPONENT</c> — RSA public exponent.</summary>
    public PublicKeyTemplateBuilder PublicExponent(ReadOnlySpan<byte> exponent)
        => Attribute(CKA.CKA_PUBLIC_EXPONENT, exponent);

    /// <summary>Sets <c>CKA_EC_PARAMS</c> — EC curve parameters (DER-encoded).</summary>
    public PublicKeyTemplateBuilder EcParams(ReadOnlySpan<byte> derParams)
        => Attribute(CKA.CKA_EC_PARAMS, derParams);
}
