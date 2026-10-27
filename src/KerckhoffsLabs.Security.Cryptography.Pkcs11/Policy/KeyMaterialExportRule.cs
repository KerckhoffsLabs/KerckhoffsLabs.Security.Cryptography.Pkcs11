namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A policy's rule for reading derived or agreed secret material off the token in the clear
/// (a <see cref="KeyMaterialExportRequest"/>). Set it with <c>CryptoPolicyBuilder.WithKeyMaterialExportRule</c>.
/// </summary>
public sealed class KeyMaterialExportRule
{
    private readonly Func<KeyMaterialExportRequest, PolicyDecision> _evaluate;

    private KeyMaterialExportRule(Func<KeyMaterialExportRequest, PolicyDecision> evaluate, string rationale)
    {
        _evaluate = evaluate;
        Rationale = rationale;
    }

    /// <summary>Refuses every read of secret key material off the token.</summary>
    public static KeyMaterialExportRule Refuse() => Refuse(
        "Reading secret key material off the token in the clear is refused; wrap it under a KEK instead.",
        kind => $"Reading the {kind} off the token violates the non-extractable-by-default posture. " +
                "Keep the secret on the token (Pkcs11Key.EncapsulateKey / DecapsulateKey / Derive to a sensitive key).");

    /// <param name="rationale">The rule's catalogue rationale.</param>
    /// <param name="denial">The refusal, from the kind of secret requested.</param>
    internal static KeyMaterialExportRule Refuse(string rationale, Func<KeyMaterialExportKind, string> denial) =>
        new(r => PolicyDecision.Deny(denial(r.Kind)), rationale);

    /// <summary>A rule backed by a delegate. Test seam: production policies use the public factories.</summary>
    internal static KeyMaterialExportRule FromDelegate(Func<KeyMaterialExportRequest, PolicyDecision> evaluate, string rationale) =>
        new(evaluate, rationale);

    /// <summary>The rule in one sentence, for the generated catalogue documentation.</summary>
    internal string Rationale { get; }

    internal PolicyDecision Evaluate(KeyMaterialExportRequest request) => _evaluate(request);
}
