using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

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
    internal override string Describe() => $"{(CKM)Mechanism.Type} for {Operation}";
    internal override CKM? MechanismType => (CKM)Mechanism.Type;
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
public sealed record RsaKeyGenerationRequest(CKM Mechanism, ulong ModulusBits) : PolicyRequest
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
