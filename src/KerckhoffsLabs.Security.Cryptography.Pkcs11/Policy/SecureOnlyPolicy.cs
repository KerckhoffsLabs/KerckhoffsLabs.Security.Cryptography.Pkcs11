using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// The default policy: an allow-list of reviewed, modern mechanisms, each for the operations it is meant
/// for. <b>Denies by default:</b> anything not on the list — unreviewed standard mechanisms,
/// vendor-defined mechanisms, unknown hashes, curves and key-agreement KDFs — is refused, whether or not
/// it also appears in the documented (but non-enforcing) deny list below. Obtain it through
/// <see cref="CryptoPolicy.SecureOnly"/>.
/// </summary>
/// <remarks>
/// <para>
/// The full generated catalogue — every allowed mechanism/hash/curve/KDF/PRF with its rationale, the
/// documented deny list, and <see cref="WithAllowedMechanism(CKM, IEnumerable{CryptoOperation}, string)"/>,
/// the extension point for adding a reviewed mechanism — is at <c>docs/policies/secure-only.md</c> in the
/// repository.
/// </para>
/// <para>
/// Beyond the allow-list, three rules apply: RSA key generation needs a modulus of at least 2048 bits, a
/// key template with <c>CKA_SENSITIVE</c> false is refused, and reading secret key material off the token
/// is refused.
/// </para>
/// <para>
/// The policy also documents notable refusals (DES/3DES, unauthenticated AES modes, ECB, MD5/SHA-1,
/// SHA-224, DSA, RSA PKCS#1 v1.5 encryption, raw RSA, Clulow's key-extraction mechanisms, …) with the
/// reason and an alternative. That list only words the denial message; it never decides a verdict — an
/// item is denied because it is not allowed, whether or not it is documented.
/// </para>
/// <para>
/// RSASSA-PKCS1-v1_5 signatures with a SHA-2/SHA-3 hash (<c>CKM_SHA256_RSA_PKCS</c>, …) stay allowed for
/// Sign and Verify: they are FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code
/// signing interop. PKCS#1 v1.5 <em>encryption</em> and raw RSA (<c>CKM_RSA_PKCS</c>, <c>CKM_RSA_X_509</c>)
/// are refused (Bleichenbacher/ROBOT padding oracles). PSS is preferred for new code.
/// </para>
/// </remarks>
public sealed partial class SecureOnlyPolicy : ICryptoPolicy
{
    private readonly PolicyCatalogue _catalogue;
    private readonly string _extensionHint;

    internal SecureOnlyPolicy()
        : this(DefaultCatalogue, "SecureOnly")
    {
    }

    private SecureOnlyPolicy(PolicyCatalogue catalogue, string name)
    {
        _catalogue = catalogue;
        Name = name;
        _extensionHint = name == ExtendedName ? ExtendedInstanceExtensionHint : ExtensionHint;
    }

    /// <summary>Appended to an unlisted-mechanism denial from <see cref="CryptoPolicy.SecureOnly"/>.</summary>
    internal const string ExtensionHint = "If you have reviewed it, add it with CryptoPolicy.SecureOnly.WithAllowedMechanism(...).";

    /// <summary>
    /// Appended to an unlisted-mechanism denial from an instance returned by
    /// <see cref="WithAllowedMechanism(CKM, IEnumerable{CryptoOperation}, string)"/>, which can itself be extended.
    /// </summary>
    internal const string ExtendedInstanceExtensionHint =
        "If you have reviewed it, add it with WithAllowedMechanism(...) on CryptoPolicy.SecureOnly or this policy.";

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public bool AllowsOverride => true;

    /// <summary>The allow-list, rules and documented deny list this instance evaluates.</summary>
    internal PolicyCatalogue Catalogue => _catalogue;

    /// <inheritdoc/>
    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return CatalogueEvaluator.Evaluate(_catalogue, Name, _extensionHint, request);
    }

    /// <summary>
    /// Hashes allowed inside OAEP / PSS parameters (SHA-2 and SHA-3 with at least 256-bit output), with
    /// their output length in bytes.
    /// </summary>
    private static readonly FrozenDictionary<CKM, int> ParamHashLengths = new Dictionary<CKM, int>
    {
        [CKM.CKM_SHA256] = 32,
        [CKM.CKM_SHA384] = 48,
        [CKM.CKM_SHA512] = 64,
        [CKM.CKM_SHA512_256] = 32,
        [CKM.CKM_SHA3_256] = 32,
        [CKM.CKM_SHA3_384] = 48,
        [CKM.CKM_SHA3_512] = 64,
    }.ToFrozenDictionary();

    private static PolicyDecision CheckOaep(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmRsaPkcsOaepParams p when ParamHashLengths.ContainsKey(p.HashAlg) => PolicyDecision.Allow,
        CkmRsaPkcsOaepParams { HashAlg: CKM.CKM_SHA_1 } => PolicyDecision.Deny(
            "SHA-1 is collision-broken; use CKM_SHA256 or stronger as the OAEP hash."),
        CkmRsaPkcsOaepParams { HashAlg: CKM.CKM_SHA224 } => PolicyDecision.Deny(
            "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit " +
            "over SHA-256 on equal-cost hardware; use CKM_SHA256 or stronger as the OAEP hash."),
        CkmRsaPkcsOaepParams p => PolicyDecision.Deny(
            $"{p.HashAlg} is not an allowed OAEP hash; use CKM_SHA256 or stronger."),
        _ => PolicyDecision.Deny(
            "CKM_RSA_PKCS_OAEP requires CkmRsaPkcsOaepParams naming SHA-256 or stronger; without them the " +
            "token chooses the hash (typically SHA-1)."),
    };

    private static PolicyDecision CheckPss(Mechanism m, CryptoOperation op) =>
        m.Parameters is CkmRsaPkcsPssParams p
            ? CheckPssParams(p)
            : PolicyDecision.Deny("CKM_RSA_PKCS_PSS requires CkmRsaPkcsPssParams naming SHA-256 or stronger.");

    /// <summary>Hash-bound PSS mechanisms fix the message hash; parameters, when given, must still be valid.</summary>
    private static PolicyDecision CheckHashedPss(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        null => PolicyDecision.Allow,
        CkmRsaPkcsPssParams p => CheckPssParams(p),
        _ => PolicyDecision.Deny("RSA-PSS parameters must be CkmRsaPkcsPssParams."),
    };

    private static PolicyDecision CheckPssParams(CkmRsaPkcsPssParams p)
    {
        if (!ParamHashLengths.TryGetValue(p.HashAlg, out int hashLength))
            return PolicyDecision.Deny($"{p.HashAlg} is not an allowed RSA-PSS hash; use CKM_SHA256 or stronger.");
        if (p.SaltLength > hashLength)
            return PolicyDecision.Deny($"A {p.SaltLength}-byte RSA-PSS salt exceeds the {hashLength}-byte {p.HashAlg} output.");
        return PolicyDecision.Allow;
    }

    /// <summary>Pre-hashes of at least 256 bits for the generic HashML-DSA / HashSLH-DSA mechanisms.</summary>
    private static readonly FrozenSet<CKM> AllowedPqcPreHashes = FrozenSet.ToFrozenSet(
    [
        CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_256,
        CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
    ]);

    private static PolicyDecision CheckPqcPreHash(Mechanism m, CryptoOperation op) =>
        m.Parameters is CkmHashPqcSignParams p && AllowedPqcPreHashes.Contains(p.Hash)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(
                "HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams with a pre-hash of at least 256 bits " +
                "(SHA-256/384/512, SHA-512/256 or SHA3-256/384/512).");

    // === KDF PRF checks ===

    /// <summary>
    /// The allow-sets the KDF PRF checks below decide the verdict from, and the single source
    /// <c>SecureOnlyPolicy.Catalogue.cs</c>'s <c>BuildAllowedKdfPrfs</c> renders into
    /// <see cref="PolicyCatalogue.AllowedKdfPrfs"/> for the generated catalogue documentation — never a hand-duplicated copy that can drift from what is enforced.
    /// </summary>
    /// <remarks>
    /// A nested type, not fields directly on <see cref="SecureOnlyPolicy"/>: a nested type's own static
    /// initializer runs on that type's first access, independent of the outer type's field-declaration
    /// order — unlike a field declared directly on <see cref="SecureOnlyPolicy"/>, which would hit the
    /// same static-field-ordering hazard <see cref="DocumentedRefusedPrfsTable"/>'s comment describes
    /// (<c>DefaultCatalogue</c>'s field initializer, in a different source file, runs before this type's
    /// other field initializers and could read an unassigned, empty set). Each <see cref="FrozenSet{T}"/>
    /// is still built exactly once — unlike a method recomputing it on every call, which the deliberately
    /// expensive <see cref="FrozenSet"/> construction (it analyses the data to pick an optimal layout)
    /// makes unfit for a per-evaluation check.
    /// </remarks>
    private static class Prfs
    {
        /// <summary>PBKDF2 PRFs allowed under SecureOnly (RFC 8018 / SP 800-132 with at least 256-bit output).</summary>
        internal static readonly FrozenSet<CKP> Pbkdf2 = FrozenSet.ToFrozenSet(
        [
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, CKP.CKP_PKCS5_PBKD2_HMAC_SHA384,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA512, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256,
        ]);

        /// <summary>SP 800-108 PRFs allowed under SecureOnly: HMAC over SHA-2/SHA-3, or AES-CMAC.</summary>
        internal static readonly FrozenSet<CKM> Sp800108 = FrozenSet.ToFrozenSet(
        [
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
            CKM.CKM_AES_CMAC,
        ]);

        /// <summary>HKDF PRFs allowed under SecureOnly: SHA-2/SHA-3, either the bare hash or its _HMAC form.</summary>
        internal static readonly FrozenSet<CKM> Hkdf = FrozenSet.ToFrozenSet(
        [
            CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
        ]);
    }

    private static PolicyDecision CheckPbkdf2Prf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmPkcs5Pbkd2Params p when Prfs.Pbkdf2.Contains(p.Prf) => PolicyDecision.Allow,
        CkmPkcs5Pbkd2Params p => DenyPrf(p.Prf.ToString(), "PBKDF2", "CKP_PKCS5_PBKD2_HMAC_SHA256 or stronger"),
        _ => PolicyDecision.Deny(
            "CKM_PKCS5_PBKD2 requires CkmPkcs5Pbkd2Params naming an allowed PRF (CKP_PKCS5_PBKD2_HMAC_SHA256 or stronger)."),
    };

    private static PolicyDecision CheckSp800108Prf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmSp800108KdfParams p when Prfs.Sp800108.Contains(p.PrfType) => PolicyDecision.Allow,
        CkmSp800108KdfParams p => DenyPrf(p.PrfType.ToString(), "SP 800-108", "CKM_SHA256_HMAC or stronger, or CKM_AES_CMAC"),
        _ => PolicyDecision.Deny(
            "SP 800-108 key derivation requires CkmSp800108KdfParams naming an allowed PRF " +
            "(CKM_SHA256_HMAC or stronger, or CKM_AES_CMAC)."),
    };

    private static PolicyDecision CheckHkdfPrf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmHkdfParams p when Prfs.Hkdf.Contains(p.PrfHashMechanism) => PolicyDecision.Allow,
        CkmHkdfParams p => DenyPrf(p.PrfHashMechanism.ToString(), "HKDF", "CKM_SHA256 or stronger, hash or _HMAC form"),
        _ => PolicyDecision.Deny(
            "CKM_HKDF_DERIVE requires CkmHkdfParams naming an allowed PRF " +
            "(CKM_SHA256 or stronger, hash or _HMAC form)."),
    };

    /// <summary>
    /// Denies a PRF that failed its family's allow-list check, naming the PRF and the family's allowed
    /// set, with the documented reason and alternative when the PRF is a documented refusal.
    /// </summary>
    private static PolicyDecision DenyPrf(string prf, string family, string allowedDescription)
    {
        if (!DocumentedRefusedPrfsTable.TryGetValue(prf, out DocumentedRefusal? refusal))
            return PolicyDecision.Deny($"{prf} is not an allowed {family} PRF; use {allowedDescription}.");

        string useAlternative = refusal.Alternative is { } a ? $" Use {a}." : "";
        return PolicyDecision.Deny($"{prf} is not allowed as a {family} PRF: {refusal.Reason}{useAlternative}");
    }
}
