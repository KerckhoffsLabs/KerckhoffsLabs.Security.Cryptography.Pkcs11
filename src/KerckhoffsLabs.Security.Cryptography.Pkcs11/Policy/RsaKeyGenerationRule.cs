namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A policy's rule for RSA key-pair generation, applied once the generation mechanism itself is allowed.
/// Set it with <c>CryptoPolicyBuilder.WithRsaKeyGenerationRule</c>.
/// </summary>
public sealed class RsaKeyGenerationRule
{
    private readonly Func<RsaKeyGenerationRequest, PolicyDecision> _evaluate;

    private RsaKeyGenerationRule(Func<RsaKeyGenerationRequest, PolicyDecision> evaluate, string rationale)
    {
        _evaluate = evaluate;
        Rationale = rationale;
    }

    /// <summary>Refuses an RSA modulus shorter than <paramref name="bits"/>.</summary>
    /// <param name="bits">The smallest modulus allowed, in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bits"/> is zero or negative.</exception>
    public static RsaKeyGenerationRule Minimum(int bits) => Minimum(
        bits,
        $"RSA key generation requires a modulus of at least {bits} bits.",
        modulus => $"RSA-{modulus} is below this policy's {bits}-bit minimum.");

    internal static RsaKeyGenerationRule Minimum(int bits, string rationale, Func<int, string> tooSmall)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bits);
        return new(r => r.ModulusBits < bits ? PolicyDecision.Deny(tooSmall(r.ModulusBits)) : PolicyDecision.Allow, rationale);
    }

    /// <summary>A rule backed by a delegate. Test seam: production policies use the public factories.</summary>
    internal static RsaKeyGenerationRule FromDelegate(Func<RsaKeyGenerationRequest, PolicyDecision> evaluate, string rationale) =>
        new(evaluate, rationale);

    /// <summary>The rule in one sentence, for the generated catalogue documentation.</summary>
    internal string Rationale { get; }

    internal PolicyDecision Evaluate(RsaKeyGenerationRequest request) => _evaluate(request);
}
