using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>An allowed <see cref="Policy.HashUseRequest"/> hash: the operations it may be used for, and why it is allowed.</summary>
/// <param name="Operations">Operations approved for this hash (typically <see cref="CryptoOperation.Sign"/> and/or <see cref="CryptoOperation.Verify"/>).</param>
/// <param name="Rationale">Why the hash is allowed — for <c>FipsOnly</c>, the NIST publication citation.</param>
internal sealed record AllowedHash(CryptoOperations Operations, string Rationale);

/// <summary>
/// The three checks a restrictive policy applies outside the mechanism/hash/curve/KDF allow-lists: the
/// RSA key-generation modulus rule, the key-template rule (<c>CKA_SENSITIVE</c>), and the key-material
/// export rule. Each policy supplies its own delegates so their rationale and thresholds can differ
/// (e.g. FipsOnly cites FIPS 186-5 in its modulus denial; SecureOnly cites SP 800-131A).
/// </summary>
/// <param name="RsaKeyGeneration">
/// Applied only once the requested mechanism has already matched an <see cref="PolicyCatalogue.AllowedMechanisms"/>
/// entry for <see cref="CryptoOperation.GenerateKeyPair"/>; typically the modulus-size floor.
/// </param>
/// <param name="KeyTemplate">Decides a <see cref="KeyTemplateRequest"/> (never gated by a table).</param>
/// <param name="KeyMaterialExport">Decides a <see cref="KeyMaterialExportRequest"/> (never gated by a table).</param>
/// <param name="RsaKeyGenerationRationale">
/// Documentation only: a human-readable description of <paramref name="RsaKeyGeneration"/>,
/// for the generated catalogue documentation. Never consulted by the evaluator.
/// </param>
/// <param name="KeyTemplateRationale">
/// Documentation only: a human-readable description of <paramref name="KeyTemplate"/>,
/// for the generated catalogue documentation. Never consulted by the evaluator.
/// </param>
/// <param name="KeyMaterialExportRationale">
/// Documentation only: a human-readable description of <paramref name="KeyMaterialExport"/>,
/// for the generated catalogue documentation. Never consulted by the evaluator.
/// </param>
internal sealed record PolicyRules(
    Func<RsaKeyGenerationRequest, PolicyDecision> RsaKeyGeneration,
    Func<KeyTemplateRequest, PolicyDecision> KeyTemplate,
    Func<KeyMaterialExportRequest, PolicyDecision> KeyMaterialExport,
    string RsaKeyGenerationRationale,
    string KeyTemplateRationale,
    string KeyMaterialExportRationale);

/// <summary>
/// The allow-list and documented deny list behind a restrictive <see cref="ICryptoPolicy"/>
/// (<c>FipsOnly</c>, <c>SecureOnly</c>). Evaluated by <see cref="CatalogueEvaluator"/>.
/// </summary>
/// <remarks>
/// The <c>Allowed*</c> and <see cref="Rules"/> members are enforced: a verdict is computed only from
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
    /// through a policy's extension point (e.g. <c>SecureOnlyPolicy.WithAllowedMechanism</c>); empty for
    /// a policy with no extension point.
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

    /// <summary>The RSA key-generation, key-template, and key-material-export rules.</summary>
    public required PolicyRules Rules { get; init; }

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
}
