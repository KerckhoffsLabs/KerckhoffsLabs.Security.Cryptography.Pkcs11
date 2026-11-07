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
    /// Allows reading the named kinds of secret key material off the token in the clear, each over the keys its scope
    /// admits, and refuses every other kind exactly as <see cref="Refuse()"/> does. This is an explicit opt-in: the secret
    /// leaves the token and lands in managed memory, so name only the kinds the application needs, the keys they may be
    /// read over, and why.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every kind is scoped by the on-token key the secret comes from, and there is no default scope: an opt-in to a
    /// kind must name its scope.
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="KeyMaterialExportKind.KdfOutput"/> needs <paramref name="kdfBaseKeys"/>. KDF output is the value of a
    /// key the token could derive from that base: over the agreed secret of <c>Pkcs11Key.DeriveSecretAgreement</c>, or
    /// an on-token master key, it would reproduce keys that were meant never to leave the token.
    /// </description></item>
    /// <item><description>
    /// <see cref="KeyMaterialExportKind.EcdhSharedSecret"/> and <see cref="KeyMaterialExportKind.KemSharedSecret"/> need
    /// <paramref name="privateKeys"/>. The secret is a function of the private key and public inputs, so over a
    /// long-lived private key it reproduces what earlier agreements and decapsulations with it kept on the token.
    /// </description></item>
    /// </list>
    /// <para>
    /// Prefer a policy allowing an export as a scoped lease (<c>Pkcs11Session.UsePolicy</c>) around the code that
    /// needs it, over the policy a session is opened with: every caller of a session can read what its policy allows.
    /// </para>
    /// </remarks>
    /// <param name="kinds">The kinds that may be read. Copied at call time; must be non-empty and defined.</param>
    /// <param name="rationale">Why the export is acceptable; shown in the policy catalogue. Must not be blank.</param>
    /// <param name="kdfBaseKeys">
    /// The base keys <see cref="KeyMaterialExportKind.KdfOutput"/> may be read over; required when
    /// <paramref name="kinds"/> names it, and only then.
    /// </param>
    /// <param name="privateKeys">
    /// The private keys <see cref="KeyMaterialExportKind.EcdhSharedSecret"/> and
    /// <see cref="KeyMaterialExportKind.KemSharedSecret"/> may be read over; required when <paramref name="kinds"/>
    /// names either, and only then.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="kinds"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="kinds"/> is empty, <paramref name="rationale"/> is blank, a kind named in
    /// <paramref name="kinds"/> has no scope, or a scope is given for a kind <paramref name="kinds"/> does not name.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">A kind is not a defined <see cref="KeyMaterialExportKind"/>.</exception>
    public static KeyMaterialExportRule Allow(
        IEnumerable<KeyMaterialExportKind> kinds,
        string rationale,
        KdfBaseKeyScope? kdfBaseKeys = null,
        PrivateKeyScope? privateKeys = null)
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
        if (kdfOutput && kdfBaseKeys is null)
            throw new ArgumentException(
                "KdfOutput needs a base-key scope: pass kdfBaseKeys (KdfBaseKeyScope.NeverProtected, Any or Where).",
                nameof(kdfBaseKeys));
        if (!kdfOutput && kdfBaseKeys is not null)
            throw new ArgumentException("A KDF base-key scope applies only to KdfOutput, which kinds does not name.", nameof(kdfBaseKeys));

        bool privateKeyKind = allowed.Contains(KeyMaterialExportKind.EcdhSharedSecret)
            || allowed.Contains(KeyMaterialExportKind.KemSharedSecret);
        if (privateKeyKind && privateKeys is null)
            throw new ArgumentException(
                "EcdhSharedSecret and KemSharedSecret need a private-key scope: pass privateKeys " +
                "(PrivateKeyScope.SessionObjects, None, Any or Where).",
                nameof(privateKeys));
        if (!privateKeyKind && privateKeys is not null)
            throw new ArgumentException(
                "A private-key scope applies only to EcdhSharedSecret and KemSharedSecret, which kinds does not name.",
                nameof(privateKeys));

        List<string> scopes = [];
        if (kdfBaseKeys is not null) scopes.Add($"KdfOutput over {kdfBaseKeys.Description}");
        if (privateKeys is not null) scopes.Add($"shared secrets over {privateKeys.Description}");
        return new(
            r => Decide(r, allowed, kdfBaseKeys, privateKeys),
            $"Reads of {string.Join(", ", copy)} are allowed ({string.Join("; ", scopes)}): {rationale.Trim()}");
    }

    private static PolicyDecision Decide(
        KeyMaterialExportRequest request,
        HashSet<KeyMaterialExportKind> allowed,
        KdfBaseKeyScope? kdfBaseKeys,
        PrivateKeyScope? privateKeys)
    {
        if (!allowed.Contains(request.Kind))
            return PolicyDecision.Deny(RefuseDenial(request.Kind));
        // Allow guarantees the scope of every allowed kind is set.
        if (request.Kind == KeyMaterialExportKind.KdfOutput)
        {
            if (!kdfBaseKeys!.Admits(request.KdfBaseKey))
                return PolicyDecision.Deny(KdfOutOfScopeDenial(request.KdfBaseKey!, kdfBaseKeys));
        }
        else if (!privateKeys!.Admits(request.PrivateKey))
        {
            return PolicyDecision.Deny(PrivateKeyOutOfScopeDenial(request.Kind, request.PrivateKey!, privateKeys));
        }
        return PolicyDecision.Allow;
    }

    private static string KdfOutOfScopeDenial(ExportKeyInfo baseKey, KdfBaseKeyScope scope) =>
        $"Reading KDF output over this {baseKey.Describe("base key")} is outside the policy's KdfOutput scope ({scope.Description}): " +
        "it would reproduce keys the token derives from that base. Derive the key on the token instead, " +
        "or widen the scope with KeyMaterialExportRule.Allow(kinds, rationale, kdfBaseKeys: ...).";

    private static string PrivateKeyOutOfScopeDenial(KeyMaterialExportKind kind, ExportKeyInfo privateKey, PrivateKeyScope scope) =>
        $"Reading the {kind} over this {privateKey.Describe("private key")} is outside the policy's private-key scope ({scope.Description}): " +
        "it would reproduce what earlier agreements or decapsulations with that key kept on the token. Keep the secret on the token " +
        "(Pkcs11Key.DeriveSecretAgreement / DecapsulateKey), or widen the scope with " +
        "KeyMaterialExportRule.Allow(kinds, rationale, privateKeys: ...).";

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
