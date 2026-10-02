using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>A policy's rule for the attribute templates of keys it lets the library create.</summary>
public sealed class KeyTemplateRule
{
    private readonly Func<KeyTemplateRequest, PolicyDecision> _evaluate;

    private KeyTemplateRule(Func<KeyTemplateRequest, PolicyDecision> evaluate, string rationale)
    {
        _evaluate = evaluate;
        Rationale = rationale;
    }

    /// <summary>
    /// Refuses a template with <c>CKA_SENSITIVE</c> false, which would let the key's value be read off the
    /// token. A true <c>CKA_EXTRACTABLE</c> is not refused: an extractable key can still only leave the
    /// token wrapped under another key.
    /// </summary>
    public static KeyTemplateRule RequireSensitive() => RequireSensitive(
        "A key template with CKA_SENSITIVE=false is refused; non-extractable (CKA_EXTRACTABLE=false) stays the default.",
        "Creating a key with CKA_SENSITIVE=false would create a non-sensitive key whose value can be read off the token.");

    internal static KeyTemplateRule RequireSensitive(string rationale, string denial) => new(
        r => r.Attributes.Any(a => a.Type == CKA.CKA_SENSITIVE && !a.GetValueAsBool())
            ? PolicyDecision.Deny(denial)
            : PolicyDecision.Allow,
        rationale);

    /// <summary>A rule backed by a delegate. Test seam: production policies use the public factories.</summary>
    internal static KeyTemplateRule FromDelegate(Func<KeyTemplateRequest, PolicyDecision> evaluate, string rationale) =>
        new(evaluate, rationale);

    internal string Rationale { get; }

    internal PolicyDecision Evaluate(KeyTemplateRequest request) => _evaluate(request);
}
