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
    public static KeyMaterialExportRule Refuse() => Refuse(RefuseRationale, RefuseDenial);

    /// <summary>
    /// Allows reading the named kinds of secret key material off the token in the clear, and refuses every other kind
    /// exactly as <see cref="Refuse()"/> does. This is an explicit opt-in: the secret leaves the token and lands in managed
    /// memory, so name only the kinds the application needs and say why.
    /// </summary>
    /// <param name="kinds">The kinds that may be read. Copied at call time; must be non-empty and defined.</param>
    /// <param name="rationale">Why the export is acceptable; shown in the policy catalogue. Must not be blank.</param>
    /// <exception cref="ArgumentException"><paramref name="kinds"/> is empty or <paramref name="rationale"/> is blank.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A kind is not a defined <see cref="KeyMaterialExportKind"/>.</exception>
    public static KeyMaterialExportRule Allow(IEnumerable<KeyMaterialExportKind> kinds, string rationale)
    {
        ArgumentNullException.ThrowIfNull(kinds);
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        KeyMaterialExportKind[] copy = [.. kinds.Distinct().Order()];
        if (copy.Length == 0) throw new ArgumentException("At least one kind must be named.", nameof(kinds));
        foreach (KeyMaterialExportKind kind in copy)
        {
            if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kinds), kind, "Not a defined KeyMaterialExportKind.");
        }
        HashSet<KeyMaterialExportKind> allowed = [.. copy];
        return new(
            r => allowed.Contains(r.Kind) ? PolicyDecision.Allow : PolicyDecision.Deny(RefuseDenial(r.Kind)),
            $"Reads of {string.Join(", ", copy)} are allowed: {rationale.Trim()}");
    }

    private const string RefuseRationale =
        "Reading secret key material off the token in the clear is refused; wrap it under a KEK instead.";

    private static string RefuseDenial(KeyMaterialExportKind kind) =>
        $"Reading the {kind} off the token violates the non-extractable-by-default posture. " +
        "Keep the secret on the token (Pkcs11Key.EncapsulateKey / DecapsulateKey / Derive to a sensitive key).";

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
