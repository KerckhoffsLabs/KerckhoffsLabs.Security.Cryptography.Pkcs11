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
    /// memory, so name only the kinds the application needs and say why. <see cref="KeyMaterialExportKind.KdfOutput"/> is
    /// allowed only over base keys in <see cref="KdfBaseKeyScope.NeverProtected"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="KeyMaterialExportKind.KdfOutput"/> is scoped by base key because its output is the value of a key the
    /// token could derive from that base: over the agreed secret of <c>Pkcs11Key.DeriveSecretAgreement</c>, or an
    /// on-token master key, it would reproduce keys that were meant never to leave the token. The default scope admits
    /// only base keys the token has not always protected (<c>CKA_ALWAYS_SENSITIVE</c> false: imported key material and
    /// keys derived from it); see <see cref="KdfBaseKeyScope"/> for its limits, and
    /// <see cref="Allow(IEnumerable{KeyMaterialExportKind}, string, KdfBaseKeyScope)"/> to choose another.
    /// </remarks>
    /// <param name="kinds">The kinds that may be read. Copied at call time; must be non-empty and defined.</param>
    /// <param name="rationale">Why the export is acceptable; shown in the policy catalogue. Must not be blank.</param>
    /// <exception cref="ArgumentException"><paramref name="kinds"/> is empty or <paramref name="rationale"/> is blank.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A kind is not a defined <see cref="KeyMaterialExportKind"/>.</exception>
    public static KeyMaterialExportRule Allow(IEnumerable<KeyMaterialExportKind> kinds, string rationale)
        => Create(kinds, rationale, KdfBaseKeyScope.NeverProtected, explicitScope: false);

    /// <summary>
    /// <see cref="Allow(IEnumerable{KeyMaterialExportKind}, string)"/>, with <see cref="KeyMaterialExportKind.KdfOutput"/>
    /// allowed over the base keys <paramref name="kdfBaseKeys"/> admits instead of the default
    /// <see cref="KdfBaseKeyScope.NeverProtected"/>.
    /// </summary>
    /// <param name="kinds">The kinds that may be read; must include <see cref="KeyMaterialExportKind.KdfOutput"/>.</param>
    /// <param name="rationale">Why the export is acceptable; shown in the policy catalogue. Must not be blank.</param>
    /// <param name="kdfBaseKeys">The base keys KDF output may be read over.</param>
    /// <exception cref="ArgumentNullException"><paramref name="kinds"/> or <paramref name="kdfBaseKeys"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="kinds"/> is empty or does not include <see cref="KeyMaterialExportKind.KdfOutput"/> (a base-key
    /// scope would then mean nothing), or <paramref name="rationale"/> is blank.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">A kind is not a defined <see cref="KeyMaterialExportKind"/>.</exception>
    public static KeyMaterialExportRule Allow(IEnumerable<KeyMaterialExportKind> kinds, string rationale, KdfBaseKeyScope kdfBaseKeys)
    {
        ArgumentNullException.ThrowIfNull(kdfBaseKeys);
        return Create(kinds, rationale, kdfBaseKeys, explicitScope: true);
    }

    private static KeyMaterialExportRule Create(
        IEnumerable<KeyMaterialExportKind> kinds, string rationale, KdfBaseKeyScope kdfBaseKeys, bool explicitScope)
    {
        ArgumentNullException.ThrowIfNull(kinds);
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        KeyMaterialExportKind[] copy = [.. kinds.Distinct().Order()];
        if (copy.Length == 0) throw new ArgumentException("At least one kind must be named.", nameof(kinds));
        int undefined = Array.FindIndex(copy, k => !Enum.IsDefined(k));
        if (undefined >= 0)
            throw new ArgumentOutOfRangeException(nameof(kinds), copy[undefined], "Not a defined KeyMaterialExportKind.");
        HashSet<KeyMaterialExportKind> allowed = [.. copy];
        bool kdfOutput = allowed.Contains(KeyMaterialExportKind.KdfOutput);
        if (explicitScope && !kdfOutput)
            throw new ArgumentException("A KDF base-key scope applies only to KdfOutput, which kinds does not name.", nameof(kinds));

        string scoped = kdfOutput ? $" (KdfOutput over {kdfBaseKeys.Description})" : "";
        return new(
            r => !allowed.Contains(r.Kind) ? PolicyDecision.Deny(RefuseDenial(r.Kind))
                : r.Kind == KeyMaterialExportKind.KdfOutput && !kdfBaseKeys.Admits(r.KdfBaseKey) ? PolicyDecision.Deny(OutOfScopeDenial(r.KdfBaseKey!, kdfBaseKeys))
                : PolicyDecision.Allow,
            $"Reads of {string.Join(", ", copy)} are allowed{scoped}: {rationale.Trim()}");
    }

    private static string OutOfScopeDenial(KdfBaseKeyInfo baseKey, KdfBaseKeyScope scope) =>
        $"Reading KDF output over this {baseKey.Describe()} is outside the policy's KdfOutput scope ({scope.Description}): " +
        "it would reproduce keys the token derives from that base. Derive the key on the token instead, " +
        "or widen the scope with KeyMaterialExportRule.Allow(kinds, rationale, kdfBaseKeys).";

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
