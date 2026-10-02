using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>An allowed <see cref="Policy.HashUseRequest"/> hash: the operations it may be used for, and why it is allowed.</summary>
/// <param name="Operations">Operations approved for this hash (typically <see cref="CryptoOperation.Sign"/> and/or <see cref="CryptoOperation.Verify"/>).</param>
/// <param name="Rationale">Why the hash is allowed — for <c>NistApproved</c>, the NIST publication citation.</param>
internal sealed record AllowedHash(CryptoOperations Operations, string Rationale);

/// <summary>
/// The allow-list and documented deny list behind a restrictive <see cref="ICryptoPolicy"/>
/// (<c>NistApproved</c>, <c>Recommended</c>). Evaluated by <see cref="CatalogueEvaluator"/>.
/// </summary>
/// <remarks>
/// The <c>Allowed*</c> and <see cref="RsaKeyGeneration"/>, <see cref="KeyTemplate"/> and <see cref="SecretExport"/> members are enforced: a verdict is computed only from
/// them. The <c>DocumentedRefused*</c> members are documentation only — see <see cref="DocumentedRefusal"/> —
/// and never change a verdict, only the wording of a denial the allow-list check already reached, and
/// what the generated catalogue documentation renders for that policy's deny list.
/// </remarks>
internal sealed class PolicyCatalogue
{
    /// <summary>Standard (<see cref="CKM"/>-typed) mechanisms, keyed by their mechanism type.</summary>
    public required FrozenDictionary<CKM, MechanismRule> AllowedMechanisms { get; init; }

    /// <summary>
    /// Vendor-defined mechanisms, keyed by their raw <c>CK_MECHANISM_TYPE</c> value. Populated only
    /// through <c>CryptoPolicyBuilder.AllowMechanism</c> with a vendor-defined value; empty for
    /// the built-in policies.
    /// </summary>
    public required FrozenDictionary<ulong, MechanismRule> AllowedVendorMechanisms { get; init; }

    /// <summary>Allowed hashes for a <see cref="HashUseRequest"/>, keyed by <see cref="System.Security.Cryptography.HashAlgorithmName.Name"/>.</summary>
    public required FrozenDictionary<string, AllowedHash> AllowedHashes { get; init; }

    /// <summary>Allowed EC curves for an <see cref="EcKeyGenerationRequest"/>, keyed by OID, mapped to a rationale.</summary>
    public required FrozenDictionary<string, string> AllowedCurves { get; init; }

    /// <summary>Allowed KDFs for a <see cref="KeyAgreementKdfRequest"/>, mapped to a rationale.</summary>
    public required FrozenDictionary<CKD, string> AllowedKdfs { get; init; }

    /// <summary>Allowed key types for a <see cref="KeyAgreementKeyRequest"/>, mapped to a rationale.</summary>
    public required FrozenDictionary<CKK, string> AllowedKeyAgreementKeyTypes { get; init; }

    /// <summary>
    /// Allowed PRFs for each KDF family (PBKDF2, SP 800-108, HKDF), keyed by a documentation label for
    /// that family, mapped to the allowed PRF values' own <c>ToString()</c> (matching the keys of
    /// <see cref="DocumentedRefusedPrfs"/>). Documentation only: the PRF parameter
    /// checks on <see cref="MechanismRule.ParameterCheck"/> decide the verdict themselves; this table
    /// only lets the generated catalogue documentation render each policy's allowed PRFs per KDF family.
    /// </summary>
    public required FrozenDictionary<string, FrozenSet<string>> AllowedKdfPrfs { get; init; }

    /// <summary>The rule applied to RSA key-pair generation once its mechanism is allowed.</summary>
    public required RsaKeyGenerationRule RsaKeyGeneration { get; init; }

    /// <summary>The rule applied to key templates.</summary>
    public required KeyTemplateRule KeyTemplate { get; init; }

    /// <summary>The rule applied to reading secret key material off the token, for a kind not in <see cref="AllowedSecretExports"/>.</summary>
    public required SecretExportRule SecretExport { get; init; }

    /// <summary>
    /// Kinds of secret key material the policy lets callers read off the token, mapped to the reason; every other kind
    /// is decided by <see cref="SecretExport"/>. Empty for both built-ins.
    /// </summary>
    public FrozenDictionary<SecretExportKind, string> AllowedSecretExports { get; init; } =
        FrozenDictionary<SecretExportKind, string>.Empty;

    /// <summary>
    /// Appended to an "unlisted mechanism" denial, pointing at how to allow it; <see langword="null"/> for none.
    /// Takes the refusing policy's identity, so a derived policy's hint names it. Never appended to hash,
    /// curve or KDF denials.
    /// </summary>
    public Func<PolicyIdentity, string>? UnlistedMechanismHint { get; init; }

    /// <summary>
    /// The expression that reaches this built-in policy (<c>CryptoPolicy.Recommended</c>), which hints use to
    /// name it; <see langword="null"/> for any other policy, a copy of a built-in included.
    /// </summary>
    public string? BuiltInReference { get; init; }

    /// <summary>
    /// Appended to a documented refusal of a mechanism, hash or curve, pointing at how to enable it for legacy
    /// interop; <see langword="null"/> for none.
    /// </summary>
    public string? LegacyUseHint { get; init; }

    /// <summary>Which built-in's extra sections the docs generator renders; <see cref="PolicyDocumentation.None"/> for any other policy.</summary>
    public PolicyDocumentation Documentation { get; init; }

    /// <summary>Documented refusals for mechanisms (documentation only; see the remarks on this type).</summary>
    public required FrozenDictionary<CKM, DocumentedRefusal> DocumentedRefusedMechanisms { get; init; }

    /// <summary>Documented refusals for hashes (documentation only; see the remarks on this type).</summary>
    public required FrozenDictionary<string, DocumentedRefusal> DocumentedRefusedHashes { get; init; }

    /// <summary>Documented refusals for EC curves, keyed by OID (documentation only; see the remarks on this type).</summary>
    public required FrozenDictionary<string, DocumentedRefusal> DocumentedRefusedCurves { get; init; }

    /// <summary>Documented refusals for KDFs (documentation only; see the remarks on this type).</summary>
    public required FrozenDictionary<CKD, DocumentedRefusal> DocumentedRefusedKdfs { get; init; }

    /// <summary>Documented refusals for key-agreement key types (documentation only; see the remarks on this type).</summary>
    public required FrozenDictionary<CKK, DocumentedRefusal> DocumentedRefusedKeyAgreementKeyTypes { get; init; }

    /// <summary>
    /// Documented refusals for KDF PRFs — the <c>CKP</c>/<c>CKM</c> pseudo-random function named inside
    /// PBKDF2 / SP 800-108 / HKDF parameters — keyed by that value's own <c>ToString()</c> (e.g.
    /// <c>"CKP_PKCS5_PBKD2_HMAC_SHA1"</c>, <c>"CKM_SHA_1_HMAC"</c>). Documentation only (see the remarks
    /// on this type): the PRF parameter checks decide the verdict themselves; this table only supplies
    /// the reason and alternative when the wording names a documented refusal, and lets the generated
    /// catalogue documentation render each policy's PRF deny list.
    /// </summary>
    public required FrozenDictionary<string, DocumentedRefusal> DocumentedRefusedPrfs { get; init; }

    /// <summary>
    /// The value for <see cref="AllowedKdfPrfs"/>: the allowed PRFs of every KDF PRF check among
    /// <paramref name="rules"/>, grouped by KDF family, so the documentation can never drift from the sets
    /// the checks enforce.
    /// </summary>
    internal static FrozenDictionary<string, FrozenSet<string>> AllowedKdfPrfsFrom(IEnumerable<MechanismRule> rules) =>
        rules.Select(r => r.ParameterCheck).OfType<KdfPrfCheck>()
             .GroupBy(c => c.Family.DocumentationLabel, StringComparer.Ordinal)
             .ToFrozenDictionary(
                 g => g.Key,
                 g => g.SelectMany(c => c.AllowedPrfs).ToFrozenSet(StringComparer.Ordinal),
                 StringComparer.Ordinal);
}

/// <summary>The built-in a catalogue documents, selecting the docs generator's policy-specific sections.</summary>
internal enum PolicyDocumentation
{
    /// <summary>A caller-built policy: no policy-specific sections.</summary>
    None,

    /// <summary>Recommended: the extension-point section and its known limits.</summary>
    Recommended,

    /// <summary>NistApproved: the FIPS 140-3 disclaimer, the NIST baseline and its known limit.</summary>
    NistApproved,
}
