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
    /// <summary>
    /// Whether the derived object can only feed a further key derivation: a <c>CKK_GENERIC_SECRET</c>
    /// with <c>CKA_DERIVE=true</c>, <c>CKA_ENCRYPT</c>, <c>CKA_DECRYPT</c>, <c>CKA_SIGN</c>,
    /// <c>CKA_VERIFY</c>, <c>CKA_WRAP</c> and <c>CKA_UNWRAP</c> all explicitly <see langword="false"/>,
    /// and neither non-sensitive nor extractable. Set by the session from the derive template, never by
    /// the caller.
    /// </summary>
    /// <remarks>
    /// With <see cref="CKD.CKD_NULL"/> that object holds the raw shared secret Z inside the module, for a
    /// key-derivation step that follows (SP 800-56C Rev.2 two-step derivation, e.g.
    /// <c>CKM_HKDF_DERIVE</c>); Z itself can never be a working key or leave the token.
    /// </remarks>
    public bool ResultIsDerivationOnlySecret { get; internal init; }

    internal override string Describe()
        => ResultIsDerivationOnlySecret ? $"{Mechanism} with {Kdf} into a derivation-only secret" : $"{Mechanism} with {Kdf}";
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

/// <summary>
/// The strength of a key that is about to be created or used: its type, size and, for post-quantum keys, its
/// parameter set. A policy that inspects keys (<c>InspectsKeys</c>) is asked before the library lets the
/// token create or use the key; the built-in <c>Recommended</c> and <c>NistApproved</c> policies allow every one.
/// A <see langword="null"/> property means the value was not reported (absent from the template, or the
/// token would not say), which a strict policy can refuse.
/// </summary>
/// <param name="KeyType">The <c>CKA_KEY_TYPE</c>, or <see langword="null"/> when not reported.</param>
/// <param name="Source">Where the description of the key comes from.</param>
public sealed record KeyStrengthRequest(CKK? KeyType, KeyStrengthSource Source) : PolicyRequest
{
    /// <summary>The <c>CKA_VALUE_LEN</c> in bytes of a symmetric key, or <see langword="null"/> when not reported.</summary>
    public int? ValueLengthBytes { get; init; }

    /// <summary>The <c>CKA_PARAMETER_SET</c> of an ML-KEM or ML-DSA key, or <see langword="null"/> when not reported.</summary>
    public ulong? ParameterSet { get; init; }

    /// <summary>The <c>CKA_HSS_LEVELS</c> of an HSS key, or <see langword="null"/> when not reported.</summary>
    public ulong? HssLevels { get; init; }

    internal override string Describe()
    {
        string text = KeyType is { } type ? $"{KeyTypeNames.Of(type)} key" : "key of unknown type";
        if (ValueLengthBytes is { } bytes)
            text += $" of {bytes} bytes";
        if (ParameterSet is { } set)
            text += $", parameter set {ParameterSetName(KeyType, set)}";
        if (HssLevels is { } levels)
            text += $", {levels} levels";
        return $"{text} ({SourceName(Source)})";
    }

    private static string ParameterSetName(CKK? keyType, ulong set) => keyType switch
    {
        CKK.CKK_ML_KEM when Enum.IsDefined(typeof(CkpMlKem), set) => ((CkpMlKem)set).ToString(),
        CKK.CKK_ML_DSA when Enum.IsDefined(typeof(CkpMlDsa), set) => ((CkpMlDsa)set).ToString(),
        _ => $"0x{set:X}",
    };

    private static string SourceName(KeyStrengthSource source) => source switch
    {
        KeyStrengthSource.Template => "template",
        KeyStrengthSource.CreatedKey => "created key",
        KeyStrengthSource.ExistingKey => "existing key",
        _ => source.ToString(),
    };
}

/// <summary>Where a <see cref="KeyStrengthRequest"/> got its description of the key.</summary>
public enum KeyStrengthSource
{
    /// <summary>The caller's template, before the token creates the key.</summary>
    Template,
    /// <summary>A key the token has just created, read back to confirm what it chose.</summary>
    CreatedKey,
    /// <summary>A key that already exists on the token, read at the moment it is used.</summary>
    ExistingKey,
}

/// <summary>Reading secret key material off the token into managed memory.</summary>
/// <param name="Kind">What is being read.</param>
public sealed record KeyMaterialExportRequest(KeyMaterialExportKind Kind) : PolicyRequest
{
    internal override string Describe() => $"export of {Kind}";
}

/// <summary>The kind of secret a <see cref="KeyMaterialExportRequest"/> reads off the token.</summary>
public enum KeyMaterialExportKind
{
    /// <summary>The raw ECDH shared secret (or a value derived from it in managed code).</summary>
    EcdhSharedSecret,
    /// <summary>A KEM shared secret (ML-KEM encapsulate/decapsulate through the BCL adapter).</summary>
    KemSharedSecret,
    /// <summary>Output bytes of an on-token KDF.</summary>
    KdfOutput,
}
