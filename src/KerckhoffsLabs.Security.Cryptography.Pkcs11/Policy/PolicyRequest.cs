using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// One security-relevant operation submitted to an <see cref="ICryptoPolicy"/>. The set of request
/// kinds is defined by this library; consumers evaluate requests but cannot define new ones.
/// </summary>
public abstract record PolicyRequest
{
    private protected PolicyRequest() { }

    /// <summary>Log- and message-safe description. Never includes attribute values or key material.</summary>
    internal abstract string Describe();

    /// <summary>The mechanism involved, when the request has one; surfaces on the violation exception.</summary>
    internal virtual CKM? MechanismType => null;
}

/// <summary>A mechanism used for an operation (encrypt, sign, derive, key generation, …).</summary>
/// <param name="Mechanism">The mechanism, including its parameters.</param>
/// <param name="Operation">What the mechanism is used for.</param>
public sealed record MechanismUseRequest(Mechanism Mechanism, CryptoOperation Operation) : PolicyRequest
{
    internal override string Describe() => $"{MechanismNames.Describe(Mechanism.Type)} for {Operation}";

    internal override CKM? MechanismType => Mechanism.Type;
}

/// <summary>A hash chosen by a managed adapter that pre-hashes before a raw on-token signature.</summary>
/// <param name="Hash">The hash algorithm.</param>
/// <param name="Operation"><see cref="CryptoOperation.Sign"/> or <see cref="CryptoOperation.Verify"/>.</param>
public sealed record HashUseRequest(HashAlgorithmName Hash, CryptoOperation Operation) : PolicyRequest
{
    internal override string Describe() => $"hash {Hash.Name} for {Operation}";
}

/// <summary>RSA key-pair generation with a given modulus size.</summary>
/// <param name="Mechanism">The key-pair generation mechanism.</param>
/// <param name="ModulusBits">The requested <c>CKA_MODULUS_BITS</c>.</param>
public sealed record RsaKeyGenerationRequest(CKM Mechanism, int ModulusBits) : PolicyRequest
{
    internal override string Describe() => $"RSA-{ModulusBits} key generation ({Mechanism})";
    internal override CKM? MechanismType => Mechanism;
}

/// <summary>EC key-pair generation on a named curve.</summary>
/// <param name="Curve">The curve.</param>
public sealed record EcKeyGenerationRequest(Pkcs11ECCurve Curve) : PolicyRequest
{
    internal override string Describe() => $"EC key generation on {Curve}";
}

/// <summary>A template for a key the token is about to create (generate, derive, unwrap, copy, create).</summary>
/// <param name="ObjectClass">The object class when the creating path knows it; otherwise <see langword="null"/>.</param>
/// <param name="Attributes">The caller's attributes. Policies must not log their values.</param>
public sealed record KeyTemplateRequest(CKO? ObjectClass, IReadOnlyList<ObjectAttribute> Attributes) : PolicyRequest
{
    internal override string Describe() => ObjectClass is { } cls ? $"key template ({cls})" : "key template";
}

/// <summary>The KDF applied to a key-agreement shared secret.</summary>
/// <param name="Mechanism">The key-agreement mechanism.</param>
/// <param name="Kdf">The KDF.</param>
public sealed record KeyAgreementKdfRequest(CKM Mechanism, CKD Kdf) : PolicyRequest
{
    internal override string Describe() => $"{Mechanism} with {Kdf}";
    internal override CKM? MechanismType => Mechanism;
}

/// <summary>The type of an existing key used for key agreement (e.g. an X25519/X448 key for ECDH).</summary>
/// <param name="Mechanism">The key-agreement mechanism.</param>
/// <param name="KeyType">The <c>CKA_KEY_TYPE</c> of the key the token will use.</param>
public sealed record KeyAgreementKeyRequest(CKM Mechanism, CKK KeyType) : PolicyRequest
{
    internal override string Describe() => $"{MechanismNames.Of(Mechanism)} with a {KeyTypeNames.Of(KeyType)} key";
    internal override CKM? MechanismType => Mechanism;
}

/// <summary>Reading secret key material off the token into managed memory.</summary>
/// <remarks>
/// <para>
/// Submitted by the read-back operations — <see cref="Pkcs11Key.DeriveAndExportSecret"/>,
/// <see cref="Pkcs11Key.EncapsulateAndExportSecret"/>, <see cref="Pkcs11Key.DecapsulateAndExportSecret"/>
/// and <see cref="Pkcs11Workspace.DeriveAndExportSecret"/> — and so by every adapter built on them. When
/// the policy allows it, the operation creates an ephemeral extractable, non-sensitive session key,
/// copies its value out and destroys it. That key's template is what the export consists of, so it is
/// not submitted again as a <see cref="KeyTemplateRequest"/>; for
/// <see cref="KeyMaterialExportKind.EcdhSharedSecret"/> with <c>CKD_NULL</c>, neither is the derivation
/// that yields the raw secret, as a <see cref="KeyAgreementKdfRequest"/>. The mechanism itself is still
/// judged as a <see cref="MechanismUseRequest"/>.
/// </para>
/// <para>
/// A custom policy can tell exports of the same kind apart by <see cref="Mechanism"/>,
/// <see cref="BaseKeyClass"/> and <see cref="BaseKeyType"/> — for example HKDF over a master key from
/// HKDF over an ECDH output.
/// </para>
/// </remarks>
/// <param name="Kind">What is being read.</param>
public sealed record KeyMaterialExportRequest(KeyMaterialExportKind Kind) : PolicyRequest
{
    /// <summary>The mechanism that produces the exported secret, when known.</summary>
    public CKM? Mechanism { get; init; }

    /// <summary>
    /// The class of the key the secret is produced from (<see cref="CKO.CKO_PRIVATE_KEY"/> for ECDH and
    /// ML-KEM decapsulation, <see cref="CKO.CKO_PUBLIC_KEY"/> for ML-KEM encapsulation,
    /// <see cref="CKO.CKO_SECRET_KEY"/> for a KDF over a secret key), or <see langword="null"/> when there
    /// is none, as for PBKDF2.
    /// </summary>
    public CKO? BaseKeyClass { get; init; }

    /// <summary>The type of the key the secret is produced from, or <see langword="null"/> when there is none.</summary>
    public CKK? BaseKeyType { get; init; }

    internal override string Describe() => Mechanism is { } m
        ? $"export of {Kind} from {MechanismNames.Of(m)}"
        : $"export of {Kind}";

    internal override CKM? MechanismType => Mechanism;
}

/// <summary>The kind of secret a <see cref="KeyMaterialExportRequest"/> reads off the token.</summary>
public enum KeyMaterialExportKind
{
    /// <summary>
    /// An ECDH shared secret: the raw secret Z (<c>CKD_NULL</c>), or the output of the token's key-agreement
    /// KDF applied to it. Allowing the raw secret already allows anything derived from it.
    /// </summary>
    EcdhSharedSecret,
    /// <summary>An ML-KEM shared secret, from encapsulation or decapsulation.</summary>
    KemSharedSecret,
    /// <summary>Output of an on-token KDF over a key: HKDF (<c>CKM_HKDF_DERIVE</c>) or SP 800-108.</summary>
    KdfOutput,
    /// <summary>Output of an on-token password-based KDF: PBKDF2 (<c>CKM_PKCS5_PBKD2</c>).</summary>
    PasswordKdfOutput,
}
