namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A policy's rule for the strength of keys (a <see cref="KeyStrengthRequest"/>). A rule either ignores keys
/// (<see cref="Unchecked"/>, the default, so the session reads nothing off the token) or inspects them.
/// </summary>
internal sealed class KeyStrengthRule
{
    private readonly Func<KeyStrengthRequest, PolicyDecision> _evaluate;

    private KeyStrengthRule(Func<KeyStrengthRequest, PolicyDecision> evaluate, string rationale, bool inspectsKeys)
    {
        _evaluate = evaluate;
        Rationale = rationale;
        InspectsKeys = inspectsKeys;
    }

    /// <summary>Allows every key and asks the session to read none.</summary>
    public static KeyStrengthRule Unchecked { get; } =
        new(_ => PolicyDecision.Allow, "Key strength is not inspected.", inspectsKeys: false);

    /// <summary>A rule that inspects keys and decides with <paramref name="evaluate"/>.</summary>
    /// <param name="evaluate">The decision for one request.</param>
    /// <param name="rationale">The rule in one sentence, for the generated catalogue documentation.</param>
    public static KeyStrengthRule FromDelegate(Func<KeyStrengthRequest, PolicyDecision> evaluate, string rationale)
    {
        ArgumentNullException.ThrowIfNull(evaluate);
        ArgumentNullException.ThrowIfNull(rationale);
        return new(evaluate, rationale, inspectsKeys: true);
    }

    /// <summary>Whether the session must describe keys to this rule (reading their attributes from the token).</summary>
    public bool InspectsKeys { get; }

    /// <summary>The rule in one sentence, for the generated catalogue documentation.</summary>
    public string Rationale { get; }

    public PolicyDecision Evaluate(KeyStrengthRequest request) => _evaluate(request);
}
