using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// Renders a <see cref="PolicyCatalogue"/> to the Markdown catalogue documentation:
/// <c>docs/policies/recommended.md</c> and <c>docs/policies/nist-approved.md</c> are the
/// committed output of <see cref="Render"/> against <c>CryptoPolicy.Recommended.Catalogue</c> and
/// <c>CryptoPolicy.NistApproved.Catalogue</c>, kept in sync by <c>PolicyDocsAreCurrentTests</c>.
/// </summary>
/// <remarks>
/// <para>
/// Deterministic by construction: every table is sorted with <see cref="StringComparer.Ordinal"/> (never
/// culture-sensitive comparison, and never raw dictionary enumeration order), every line ends with
/// <c>\n</c> (never <c>\r\n</c> — this type never calls <c>AppendLine</c> or uses
/// <see cref="Environment.NewLine"/>), and nothing here reads the clock, the machine, or any
/// environment/culture setting. The same catalogue renders byte-for-byte identically on every run and
/// every machine.
/// </para>
/// <para>
/// Mechanisms are grouped into a documentation-only "family" (AES, EC, RSA signature, …) derived purely
/// from the standard <c>CKM_*</c> name by <see cref="MechanismFamily"/> — a naming-based helper, not a
/// field on <see cref="MechanismRule"/>: with roughly 150 allow/deny-listed mechanisms already organised
/// by source-code region under a handful of recurring prefixes, pattern-matching the name is far less
/// invasive than threading a new required field through every <c>Allow</c>/<c>Refuse</c> call site in
/// both catalogues, and it can never drift out of sync with a rule's actual content the way a
/// hand-maintained field could. A family is documentation only: it never affects evaluation, only where
/// a mechanism is printed on the page and next to which other mechanisms.
/// </para>
/// </remarks>
internal static class PolicyCatalogueMarkdown
{
    private const string Footer = "Anything not listed above is denied by default.";

    /// <summary>Markdown header-separator row for a two-column table.</summary>
    private const string TwoColumnSeparator = "|---|---|";

    /// <summary>Markdown header-separator row for a three-column table.</summary>
    private const string ThreeColumnSeparator = "|---|---|---|";

    /// <summary>
    /// Known limits applicable to every restrictive policy. The policy-specific limits
    /// (<see cref="RecommendedKnownLimits"/>, <see cref="FipsKnownLimits"/>) are appended after them.
    /// </summary>
    private static readonly string[] SharedKnownLimits =
    [
        "The size and curve of keys already on the token are not inspected: using an existing key that would "
            + "not pass generation (a short RSA modulus, a weak curve, …) is not refused. Only an ECDH key's type "
            + "is checked.",
        "Raw `CKM_ECDSA`, `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign a caller-computed digest; the hash that "
            + "produced it is not visible to the policy.",
    ];

    /// <summary>
    /// Known limits of the Recommended family alone: NistApproved refuses <c>CKM_AES_KEY_WRAP_PAD</c> outright.
    /// </summary>
    private static readonly string[] RecommendedKnownLimits =
    [
        "`CKM_AES_KEY_WRAP_PAD` is allowed, but its padding is vendor-defined: some tokens implement RFC 5649 "
            + "(KWP), others KW over PKCS#7-padded input, so a key wrapped on one token may not unwrap on "
            + "another. Prefer `CKM_AES_KEY_WRAP_KWP` where the token supports it.",
    ];

    /// <summary>
    /// Known limits of NistApproved alone.
    /// </summary>
    private static readonly string[] FipsKnownLimits =
    [
        "NistApproved restricts what this library sends to the token. FIPS 140-3 compliance also requires a "
            + "validated cryptographic module operating in its approved mode.",
    ];

    /// <summary>Renders <paramref name="catalogue"/> as the full Markdown catalogue page for the policy named <paramref name="policyName"/>.</summary>
    /// <param name="catalogue">The allow-list, rules and documented deny list to render.</param>
    /// <param name="policyName">
    /// <c>"Recommended"</c> or <c>"NistApproved"</c> — selects the policy-specific sections: the
    /// <c>ToBuilder</c> extension-point paragraph for the Recommended family (a name starting
    /// with <c>"Recommended"</c>), or the FIPS 140-3 disclaimer, NIST baseline, and extra known limit for
    /// <c>"NistApproved"</c>.
    /// </param>
    public static string Render(PolicyCatalogue catalogue, string policyName)
    {
        ArgumentNullException.ThrowIfNull(catalogue);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        bool isRecommendedFamily = catalogue.Documentation == PolicyDocumentation.Recommended;
        bool isNistApproved = catalogue.Documentation == PolicyDocumentation.NistApproved;

        var sb = new StringBuilder();
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line($"# {policyName} policy catalogue");
        Line();
        Line("*Generated from the `" + policyName + "` policy catalogue by `PolicyCatalogueMarkdown`; do not edit by hand.*");
        Line();

        if (isRecommendedFamily)
        {
            Line(
                "An allow-list of reviewed, modern mechanisms, hashes, curves, key-agreement KDFs and KDF PRFs. "
                + "Anything not on the list below — including every vendor-defined mechanism — is denied by "
                + "default, whether or not it also appears in the documented deny list further down this page.");
        }
        else
        {
            Line(
                "An allow-list of NIST-approved security functions, per a fixed snapshot of NIST guidance (see "
                + "the baseline below). Anything not on the list below — including every vendor-defined "
                + "mechanism — is denied by default, whether or not it also appears in the documented deny "
                + "list further down this page.");
        }
        Line();

        if (isNistApproved)
        {
            Line("> **`NistApproved` is not a FIPS 140-3 certification.** It restricts what this library sends to the " +
                 "token; FIPS 140-3 compliance also requires a validated cryptographic module operating in its " +
                 "approved mode.");
            Line(">");
            Line($"> Baseline: {Escape(NistApprovedDefinition.Baseline)}");
            Line();
        }

        RenderAllowedMechanisms(sb, catalogue);
        RenderAllowedHashes(sb, catalogue);
        RenderAllowedCurves(sb, catalogue);
        RenderAllowedKdfs(sb, catalogue);
        RenderAllowedKeyAgreementKeyTypes(sb, catalogue);
        RenderAllowedKdfPrfs(sb, catalogue);
        RenderAllowedSecretExports(sb, catalogue);
        RenderRules(sb, catalogue);
        RenderDocumentedRefusals(sb, catalogue);

        if (isRecommendedFamily)
        {
            Line("## Extension point");
            Line();
            Line(
                "`CryptoPolicy.Recommended.ToBuilder(name)` returns a `CryptoPolicyBuilder` holding a copy of every rule on "
                + "this page; `AllowMechanism(...)` on it allows one more mechanism for the operations and reason you supply "
                + "— including a mechanism listed under Documented refusals above, and any vendor-defined mechanism — and "
                + "`Build()` returns the new policy under your name. Allowing an already-allowed mechanism adds operations and "
                + "keeps its parameter check. `AllowSecretExport(...)`, `AllowCurve(...)` and `AllowKeyAgreementKdf(...)` "
                + "likewise allow one kind of secret read-back, one EC curve or one key-agreement KDF. "
                + "`ToBuilder` never modifies `CryptoPolicy.Recommended` itself.");
            Line();
        }

        Line("## Known limits");
        Line();
        foreach (string limit in SharedKnownLimits)
            Line($"- {Escape(limit)}");
        if (isRecommendedFamily)
        {
            foreach (string limit in RecommendedKnownLimits)
                Line($"- {Escape(limit)}");
        }
        if (isNistApproved)
        {
            foreach (string limit in FipsKnownLimits)
                Line($"- {Escape(limit)}");
        }
        Line();

        Line("---");
        Line();
        Line(Footer);

        return sb.ToString();
    }

    // === Allowed mechanisms ===

    private static void RenderAllowedMechanisms(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed mechanisms");
        Line();

        foreach (var (family, entries) in GroupMechanismsByFamily(catalogue.AllowedMechanisms))
        {
            Line($"### {family}");
            Line();
            Line("| Mechanism | Operations | Legacy operations | Parameter check | Rationale |");
            Line("|---|---|---|---|---|");
            foreach (var (name, rule) in entries)
            {
                string operations = rule.Operations == CryptoOperations.None ? "—" : CatalogueEvaluator.FormatOperations(rule.Operations);
                string legacy = rule.LegacyOperations == CryptoOperations.None ? "—" : CatalogueEvaluator.FormatOperations(rule.LegacyOperations);
                string check = rule.ParameterCheck is null ? "—" : Escape(rule.ParameterCheck.Description);
                Line($"| `{name}` | {Escape(operations)} | {Escape(legacy)} | {check} | {Escape(rule.Rationale)} |");
            }
            Line();
        }

        if (catalogue.AllowedVendorMechanisms.Count > 0)
        {
            Line("### Vendor mechanisms");
            Line();
            Line("| Mechanism value | Operations | Legacy operations | Parameter check | Rationale |");
            Line("|---|---|---|---|---|");
            foreach ((ulong raw, MechanismRule rule) in catalogue.AllowedVendorMechanisms.OrderBy(kv => kv.Key))
            {
                string operations = rule.Operations == CryptoOperations.None ? "—" : CatalogueEvaluator.FormatOperations(rule.Operations);
                string legacy = rule.LegacyOperations == CryptoOperations.None ? "—" : CatalogueEvaluator.FormatOperations(rule.LegacyOperations);
                string check = rule.ParameterCheck is null ? "—" : Escape(rule.ParameterCheck.Description);
                string value = "0x" + raw.ToString("X", CultureInfo.InvariantCulture);
                Line($"| `{value}` | {Escape(operations)} | {Escape(legacy)} | {check} | {Escape(rule.Rationale)} |");
            }
            Line();
        }
    }

    // === Allowed hashes / curves / KDFs / KDF PRFs ===

    private static void RenderAllowedHashes(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed hashes");
        Line();
        Line("| Hash | Operations | Rationale |");
        Line(ThreeColumnSeparator);
        foreach ((string name, AllowedHash hash) in catalogue.AllowedHashes.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            Line($"| `{Escape(name)}` | {Escape(CatalogueEvaluator.FormatOperations(hash.Operations))} | {Escape(hash.Rationale)} |");
        Line();
    }

    private static void RenderAllowedCurves(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed EC curves");
        Line();
        Line("| Curve | OID | Rationale |");
        Line(ThreeColumnSeparator);
        foreach ((string oid, string rationale) in catalogue.AllowedCurves.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            Line($"| {Escape(CurveFriendlyName(oid))} | `{Escape(oid)}` | {Escape(rationale)} |");
        Line();
    }

    private static void RenderAllowedKdfs(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed key-agreement KDFs");
        Line();
        Line("| KDF | Rationale |");
        Line(TwoColumnSeparator);
        foreach ((CKD kdf, string rationale) in catalogue.AllowedKdfs.OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal))
            Line($"| `{Escape(kdf.ToString())}` | {Escape(rationale)} |");
        Line();
    }

    private static void RenderAllowedKeyAgreementKeyTypes(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed key-agreement key types");
        Line();
        Line("The `CKA_KEY_TYPE` of the existing key an ECDH derivation or KEM uses (`CKM_ECDH1_DERIVE` serves both kinds).");
        Line();
        Line("| Key type | Rationale |");
        Line(TwoColumnSeparator);
        foreach ((CKK keyType, string rationale) in catalogue.AllowedKeyAgreementKeyTypes.OrderBy(kv => KeyTypeNames.Of(kv.Key), StringComparer.Ordinal))
            Line($"| `{Escape(KeyTypeNames.Of(keyType))}` | {Escape(rationale)} |");
        Line();
    }

    private static void RenderAllowedKdfPrfs(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed KDF PRFs");
        Line();
        Line("Per-family allow-list for the PRF named inside PBKDF2 / SP 800-108 / HKDF mechanism parameters.");
        Line();
        Line("| KDF family | Allowed PRFs |");
        Line(TwoColumnSeparator);
        foreach ((string family, FrozenSet<string> prfs) in catalogue.AllowedKdfPrfs.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            string prfList = string.Join(", ", prfs.Order(StringComparer.Ordinal).Select(p => $"`{Escape(p)}`"));
            Line($"| {Escape(family)} | {prfList} |");
        }
        Line();
    }

    private static void RenderAllowedSecretExports(StringBuilder sb, PolicyCatalogue catalogue)
    {
        if (catalogue.AllowedSecretExports.Count == 0)
            return;

        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Allowed secret exports");
        Line();
        Line("Kinds of secret key material this policy lets callers read off the token; the export rule below refuses every other kind.");
        Line();
        Line("| Kind | Rationale |");
        Line(TwoColumnSeparator);
        foreach ((SecretExportKind kind, string rationale) in catalogue.AllowedSecretExports.OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal))
            Line($"| `{kind}` | {Escape(rationale)} |");
        Line();
    }

    // === Rules ===

    private static void RenderRules(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Rules");
        Line();
        Line(
            "Beyond the allow-lists above, three rules apply: the modulus rule to RSA key-pair generation "
            + "requests, the template rule to key templates the library creates keys from, and the export rule to "
            + "every read of secret key material off the token.");
        Line();
        Line("| Rule | Rationale |");
        Line(TwoColumnSeparator);
        Line($"| RSA key-pair generation modulus | {Escape(catalogue.RsaKeyGeneration.Rationale)} |");
        Line($"| Key template (`CKA_SENSITIVE`) | {Escape(catalogue.KeyTemplate.Rationale)} |");
        Line($"| Secret export | {Escape(catalogue.SecretExport.Rationale)} |");
        Line();
    }

    // === Documented refusals ===

    private static void RenderDocumentedRefusals(StringBuilder sb, PolicyCatalogue catalogue)
    {
        void Line(string text = "") => sb.Append(text).Append('\n');

        Line("## Documented refusals");
        Line();
        Line(
            "Documentation only: every item below is refused because it is absent from the allow-lists above. "
            + "This table only explains *why* it was considered and refused, rather than simply never reviewed; "
            + "removing an entry here never allows the item.");
        Line();

        Line("### Mechanisms");
        Line();
        foreach (var (family, entries) in GroupRefusalsByFamily(catalogue.DocumentedRefusedMechanisms))
        {
            Line($"#### {family}");
            Line();
            Line("| Mechanism | Reason | Alternative |");
            Line(ThreeColumnSeparator);
            foreach (var (name, refusal) in entries)
                Line($"| `{name}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
            Line();
        }

        Line("### Hashes");
        Line();
        Line("| Hash | Reason | Alternative |");
        Line(ThreeColumnSeparator);
        foreach ((string name, DocumentedRefusal refusal) in catalogue.DocumentedRefusedHashes.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            Line($"| `{Escape(name)}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
        Line();

        Line("### EC curves");
        Line();
        Line("| Curve | OID | Reason | Alternative |");
        Line("|---|---|---|---|");
        foreach ((string oid, DocumentedRefusal refusal) in catalogue.DocumentedRefusedCurves.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            Line($"| {Escape(CurveFriendlyName(oid))} | `{Escape(oid)}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
        Line();

        Line("### Key-agreement KDFs");
        Line();
        Line("| KDF | Reason | Alternative |");
        Line(ThreeColumnSeparator);
        foreach ((CKD kdf, DocumentedRefusal refusal) in catalogue.DocumentedRefusedKdfs.OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal))
            Line($"| `{Escape(kdf.ToString())}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
        Line();

        if (catalogue.DocumentedRefusedKeyAgreementKeyTypes.Count > 0)
        {
            Line("### Key-agreement key types");
            Line();
            Line("| Key type | Reason | Alternative |");
            Line(ThreeColumnSeparator);
            foreach ((CKK keyType, DocumentedRefusal refusal) in catalogue.DocumentedRefusedKeyAgreementKeyTypes.OrderBy(kv => KeyTypeNames.Of(kv.Key), StringComparer.Ordinal))
                Line($"| `{Escape(KeyTypeNames.Of(keyType))}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
            Line();
        }

        Line("### KDF PRFs");
        Line();
        Line("| PRF | Reason | Alternative |");
        Line(ThreeColumnSeparator);
        foreach ((string prf, DocumentedRefusal refusal) in catalogue.DocumentedRefusedPrfs.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            Line($"| `{Escape(prf)}` | {Escape(refusal.Reason)} | {RefusalAlternative(refusal)} |");
        Line();
    }

    private static string RefusalAlternative(DocumentedRefusal refusal)
        => refusal.Alternative is { } alternative ? Escape(alternative) : "—";

    // === Family grouping (documentation only; see the remarks on this type) ===

    private static IEnumerable<(string Family, IEnumerable<(string Name, MechanismRule Rule)> Entries)> GroupMechanismsByFamily(
        FrozenDictionary<CKM, MechanismRule> mechanisms)
        => mechanisms
            .Select(kv => (Name: MechanismNames.Of(kv.Key), Family: MechanismFamily(kv.Key), kv.Value))
            .GroupBy(e => e.Family, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => (g.Key, g.OrderBy(e => e.Name, StringComparer.Ordinal).Select(e => (e.Name, e.Value))));

    private static IEnumerable<(string Family, IEnumerable<(string Name, DocumentedRefusal Refusal)> Entries)> GroupRefusalsByFamily(
        FrozenDictionary<CKM, DocumentedRefusal> refusals)
        => refusals
            .Select(kv => (Name: MechanismNames.Of(kv.Key), Family: MechanismFamily(kv.Key), kv.Value))
            .GroupBy(e => e.Family, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => (g.Key, g.OrderBy(e => e.Name, StringComparer.Ordinal).Select(e => (e.Name, e.Value))));

    /// <summary>
    /// Ordered (most-specific-first) family rules for <see cref="MechanismFamily"/>: a name can contain
    /// several tokens (e.g. <c>CKM_SHA256_RSA_PKCS_PSS</c> contains both <c>SHA</c> and <c>RSA</c>), and
    /// the first matching rule wins. Table-driven so the family classifier itself stays a small loop —
    /// see the remarks on <see cref="PolicyCatalogueMarkdown"/> for why family is naming-based at all.
    /// </summary>
    private static readonly (Func<string, bool> Matches, string Family)[] FamilyRules =
    [
        (n => Has(n, "ML_KEM") || Has(n, "ML_DSA") || Has(n, "SLH_DSA"), "Post-quantum"),
        (n => Has(n, "SP800_108") || Has(n, "HKDF") || Has(n, "PBKD2"), "KDF"),
        (n => Has(n, "KEY_DERIVATION") || Has(n, "KEY_DERIVE") || Has(n, "CONCATENATE") || Has(n, "XOR_BASE")
            || Has(n, "EXTRACT_KEY_FROM_KEY") || Has(n, "IKE"), "Key derivation"),
        (n => Has(n, "ECDSA") || Has(n, "EDDSA") || Has(n, "EC_KEY_PAIR_GEN") || Has(n, "EC_EDWARDS") || Has(n, "EC_MONTGOMERY") || Has(n, "ECDH"), "EC"),
        (n => Has(n, "DSA"), "DSA"),
        (n => Has(n, "RSA") && Has(n, "KEY_PAIR_GEN"), "RSA key generation"),
        (n => Has(n, "RSA") && Has(n, "OAEP"), "RSA encryption"),
        (n => Has(n, "RSA"), "RSA signature"),
        (n => Has(n, "AES"), "AES"),
        (n => Has(n, "CHACHA20") || Has(n, "SALSA20"), "ChaCha20 / Salsa20"),
        (n => Has(n, "DES"), "DES / TDEA"),
        // GOST checked before the digest rule below: several GOST mechanisms embed a digest-looking
        // token in their own name (CKM_GOSTR3410_WITH_GOSTR3411 and CKM_GOSTR3411_HMAC contain
        // "GOSTR3411"; CKM_GOSTR3411 itself is exactly that token) despite being GOST signature/MAC
        // mechanisms, not generic digests — they must group with their CKM_GOST28147_*/CKM_GOSTR3410_*
        // siblings under "Legacy ciphers", not split off into "Digest / HMAC".
        (n => Has(n, "GOST"), "Legacy ciphers"),
        (n => Has(n, "SHA") || Has(n, "MD2") || Has(n, "MD5") || Has(n, "RIPEMD") || Has(n, "HMAC") || Has(n, "GENERIC_SECRET"), "Digest / HMAC"),
        (n => Has(n, "CAST") || Has(n, "RC2") || Has(n, "RC4") || Has(n, "RC5") || Has(n, "BLOWFISH") || Has(n, "IDEA") || Has(n, "SEED")
            || Has(n, "SKIPJACK"), "Legacy ciphers"),
    ];

    private static bool Has(string name, string token) => name.Contains(token, StringComparison.Ordinal);

    /// <summary>
    /// Assigns a documentation-only family label to a standard mechanism, purely from its <c>CKM_*</c>
    /// name, by evaluating <see cref="FamilyRules"/> in order — see the remarks on
    /// <see cref="PolicyCatalogueMarkdown"/> for why this is a naming-based helper rather than a field.
    /// </summary>
    internal static string MechanismFamily(CKM mechanism)
    {
        string name = MechanismNames.Of(mechanism);
        foreach ((Func<string, bool> matches, string family) in FamilyRules)
        {
            if (matches(name)) return family;
        }

        return "Other";
    }

    /// <summary>A curve's <c>Family (OID)</c>-style friendly cell for its OID, falling back to just the OID when unknown.</summary>
    private static string CurveFriendlyName(string oid)
    {
        Pkcs11ECCurve curve = Pkcs11ECCurve.CreateFromValue(oid);
        return curve.FriendlyName is { } name ? $"`{name}`" : "*(unnamed)*";
    }

    /// <summary>Escapes Markdown table-breaking characters: <c>|</c>, and any literal newline.</summary>
    private static string Escape(string text)
        => text.Replace("\r\n", " ", StringComparison.Ordinal)
               .Replace("\n", " ", StringComparison.Ordinal)
               .Replace("|", "\\|", StringComparison.Ordinal);
}
