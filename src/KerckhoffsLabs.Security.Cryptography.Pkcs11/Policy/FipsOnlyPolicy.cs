using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// Allows only NIST-approved security functions, per a fixed snapshot of NIST guidance
/// (<see cref="Baseline"/>). Anything not on the list — including vendor-defined mechanisms — is refused.
/// </summary>
/// <remarks>
/// This restricts what the library sends to the token; it does not make an application FIPS 140-3
/// compliant, which also requires a validated module operating in its approved mode. AES key wrapping is
/// approved only via KW/KWP (<c>CKM_AES_KEY_WRAP</c>, <c>CKM_AES_KEY_WRAP_KWP</c>) or the GCM/CCM modes;
/// <c>CKM_AES_KEY_WRAP_PAD</c>, whose padding is vendor-defined, is refused. Other AES modes encrypt and
/// decrypt data but may not wrap or unwrap keys. ECDH with an existing Montgomery (X25519/X448) key is refused through
/// <see cref="KeyAgreementKeyRequest"/>, which the session raises with the key's <c>CKA_KEY_TYPE</c>.
/// Known limits (mirrored in the public <see cref="CryptoPolicy.FipsOnly"/> docs): the key sizes and curves
/// of existing keys, and the ML-DSA / SLH-DSA parameter set behind a pre-hash mechanism, are not inspected. (The KDF inside
/// <c>CK_ECDH1_DERIVE_PARAMS</c>, judged as a <see cref="KeyAgreementKdfRequest"/> on every ECDH derivation
/// and KEM, and the PRF inside SP 800-108, HKDF and PBKDF2 parameters <i>are</i> checked — see
/// <see cref="CheckSp800108Prf"/>, <see cref="CheckHkdfPrf"/>, <see cref="CheckPbkdf2Prf"/>.) The EC curve is
/// judged through <see cref="EcKeyGenerationRequest"/> on every <c>CKM_EC_KEY_PAIR_GEN</c> generation,
/// whichever public entry point it comes through. Raw <c>CKM_RSA_PKCS</c> signing and raw <c>CKM_ECDSA</c>
/// cannot see which digest the caller pre-computed, so both are approved without checking it.
/// </remarks>
internal sealed partial class FipsOnlyPolicy : ICryptoPolicy
{
    /// <summary>The NIST publications this table reflects.</summary>
    internal const string Baseline =
        "SP 800-131A Rev.2; SP 800-140C Rev.2 / SP 800-140D Rev.2 (CMVP lists of 2026-08-21); FIPS 186-5; SP 800-186; FIPS 203/204/205";

    public string Name => "FipsOnly";
    public bool AllowsOverride => false;

    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return CatalogueEvaluator.Evaluate(Catalogue, Name, extensionHint: null, request);
    }

    /// <summary>Approved hashes (FIPS 180-4 / FIPS 202) usable inside OAEP / PSS, with their output length in bytes.</summary>
    private static readonly FrozenDictionary<CKM, int> ParamHashLengths = new Dictionary<CKM, int>
    {
        [CKM.CKM_SHA_1] = 20,
        [CKM.CKM_SHA224] = 28,
        [CKM.CKM_SHA256] = 32,
        [CKM.CKM_SHA384] = 48,
        [CKM.CKM_SHA512] = 64,
        [CKM.CKM_SHA512_224] = 28,
        [CKM.CKM_SHA512_256] = 32,
        [CKM.CKM_SHA3_224] = 28,
        [CKM.CKM_SHA3_256] = 32,
        [CKM.CKM_SHA3_384] = 48,
        [CKM.CKM_SHA3_512] = 64,
    }.ToFrozenDictionary();

    /// <summary>
    /// Pre-hashes with at least 128-bit collision strength, the floor set by the smallest ML-DSA / SLH-DSA
    /// parameter sets. PKCS#11 defines no SHAKE digest mechanism to name here; SHAKE pre-hashing is
    /// available through the dedicated <c>CKM_HASH_*_SHAKE128/256</c> mechanisms.
    /// </summary>
    private static readonly FrozenSet<CKM> ApprovedPqcPreHashes = FrozenSet.ToFrozenSet(
    [
        CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
        CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
    ]);

    private static PolicyDecision CheckPqcPreHash(Mechanism m, CryptoOperation op) =>
        m.Parameters is CkmHashPqcSignParams p && ApprovedPqcPreHashes.Contains(p.Hash)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(
                "FIPS 204 §5.4 / FIPS 205 §10: HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams with a pre-hash " +
                "of at least 128-bit collision strength (SHA-256/384/512 or SHA3-256/384/512).");

    // SP 800-56B Rev.2 §5.1 / §7.2.2.1: OAEP needs an approved hash. SHA-1 qualifies — it is approved
    // (FIPS 180-4) and acceptable outside digital signatures (SP 800-131A Rev.2 Table 8).
    private static PolicyDecision CheckOaep(Mechanism m, CryptoOperation op) =>
        m.Parameters is CkmRsaPkcsOaepParams p && ParamHashLengths.ContainsKey(p.HashAlg)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny("SP 800-56B Rev.2 §7.2.2.1: RSA-OAEP requires CkmRsaPkcsOaepParams with an approved hash.");

    private static PolicyDecision CheckPss(Mechanism m, CryptoOperation op) =>
        m.Parameters is CkmRsaPkcsPssParams p
            ? CheckPssParams(p, op)
            : PolicyDecision.Deny("FIPS 186-5 §5.4: RSA-PSS requires CkmRsaPkcsPssParams with an approved hash.");

    /// <summary>Hash-bound PSS mechanisms fix the message hash; parameters, when given, must still be valid.</summary>
    private static PolicyDecision CheckHashedPss(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        null => PolicyDecision.Allow,
        CkmRsaPkcsPssParams p => CheckPssParams(p, op),
        _ => PolicyDecision.Deny("FIPS 186-5 §5.4: RSA-PSS parameters must be CkmRsaPkcsPssParams."),
    };

    private static PolicyDecision CheckPssParams(CkmRsaPkcsPssParams p, CryptoOperation op)
    {
        if (!ParamHashLengths.TryGetValue(p.HashAlg, out int hashLength))
            return PolicyDecision.Deny($"FIPS 186-5 §5.4(b): {p.HashAlg} is not an approved hash for RSA-PSS.");
        if (p.HashAlg == CKM.CKM_SHA_1 && op != CryptoOperation.Verify)
            return PolicyDecision.Deny($"SP 800-131A Rev.2 §9: {p.HashAlg} is not approved for RSA-PSS {op}.");
        if (p.SaltLength > hashLength)
            return PolicyDecision.Deny($"FIPS 186-5 §5.4(g): a {p.SaltLength}-byte salt exceeds the {hashLength}-byte {p.HashAlg} output.");
        return PolicyDecision.Allow;
    }

    // === AEAD tag-length checks ===

    // SP 800-38D §5.2.1.2 approves 128-, 120-, 112-, 104- and 96-bit GCM tags for general use; 64 and
    // 32 bits only under Appendix C's conditions on the protocol, which a policy cannot verify, and no
    // other length at all. SP 800-38C Appendix B.2: a CCM MAC below 64 bits "shall not be used without
    // a careful analysis of the risks", which a policy cannot perform either.
    private const int MinGcmTagBits = 96;
    private const int MinCcmMacBits = 64;

    /// <summary>
    /// The tag of AES-GCM, in either <see cref="CkmAesGcmParams"/> or <see cref="CkmGcmMessageParams"/>.
    /// A mechanism without parameters passes: the message API judges the call with its per-message
    /// parameters instead, and a classic call without them fails at the token.
    /// </summary>
    private static PolicyDecision CheckGcmTag(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmAesGcmParams p => RequireGcmTagBits(p.TagBits),
        CkmGcmMessageParams p => RequireGcmTagBits(8 * p.TagLength),
        null when !m.HasRawParameter => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(
            "SP 800-38D §5.2.1.2: AES-GCM requires CkmAesGcmParams or CkmGcmMessageParams, so the tag length can be checked."),
    };

    private static PolicyDecision RequireGcmTagBits(int tagBits) =>
        tagBits >= MinGcmTagBits
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(
                $"SP 800-38D §5.2.1.2: a {tagBits}-bit tag is not approved for general use; use 96, 104, 112, 120 or 128 bits.");

    /// <summary>
    /// The MAC of AES-CCM, in either <see cref="CkmAesCcmParams"/> or <see cref="CkmCcmMessageParams"/>;
    /// a mechanism without parameters passes, as for AES-GCM.
    /// </summary>
    private static PolicyDecision CheckCcmMac(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmAesCcmParams p => RequireCcmMacBits(8 * p.MacLength),
        CkmCcmMessageParams p => RequireCcmMacBits(8 * p.MacLength),
        null when !m.HasRawParameter => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(
            "SP 800-38C: AES-CCM requires CkmAesCcmParams or CkmCcmMessageParams, so the MAC length can be checked."),
    };

    private static PolicyDecision RequireCcmMacBits(int macBits) =>
        macBits >= MinCcmMacBits
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(
                $"SP 800-38C Appendix B.2: a {macBits}-bit MAC is below 64 bits, which requires a risk analysis this policy cannot perform.");

    // === KDF PRF checks ===

    /// <summary>
    /// The approved-sets the KDF PRF checks below decide the verdict from, and the single source
    /// <c>FipsOnlyPolicy.Rules.cs</c>'s <c>BuildAllowedKdfPrfs</c> renders into
    /// <see cref="PolicyCatalogue.AllowedKdfPrfs"/> for the generated catalogue documentation — never a hand-duplicated copy that can drift from what is enforced.
    /// </summary>
    /// <remarks>
    /// A nested type, not fields directly on <see cref="FipsOnlyPolicy"/>: a nested type's own static
    /// initializer runs on that type's first access, independent of the outer type's field-declaration
    /// order — unlike a field declared directly on <see cref="FipsOnlyPolicy"/>, which would hit the same
    /// static-field-ordering hazard <see cref="DocumentedRefusedPrfsTable"/>'s comment describes
    /// (<c>Catalogue</c>'s field initializer, in a different source file, runs before this type's other
    /// field initializers and could read an unassigned, empty set). Each <see cref="FrozenSet{T}"/> is
    /// still built exactly once — unlike a method recomputing it on every call, which the deliberately
    /// expensive <see cref="FrozenSet"/> construction (it analyses the data to pick an optimal layout)
    /// makes unfit for a per-evaluation check.
    /// </remarks>
    private static class Prfs
    {
        /// <summary>PBKDF2 PRFs approved by SP 800-132: every defined HMAC variant except the non-approved GOST one.</summary>
        internal static readonly FrozenSet<CKP> Pbkdf2 = FrozenSet.ToFrozenSet(
        [
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA224, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA384, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_224, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256,
        ]);

        /// <summary>SP 800-108 PRFs approved: HMAC over an approved hash (<see cref="ParamHashLengths"/>), or AES-CMAC.</summary>
        internal static readonly FrozenSet<CKM> Sp800108 = FrozenSet.ToFrozenSet(
        [
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_256_HMAC,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
            CKM.CKM_AES_CMAC,
        ]);

        /// <summary>HKDF PRFs approved: an approved hash (<see cref="ParamHashLengths"/>), either the bare hash or its _HMAC form.</summary>
        internal static readonly FrozenSet<CKM> Hkdf = FrozenSet.ToFrozenSet(
        [
            CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA512_224, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_256_HMAC,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
        ]);
    }

    private static PolicyDecision CheckPbkdf2Prf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmPkcs5Pbkd2Params p when Prfs.Pbkdf2.Contains(p.Prf) => PolicyDecision.Allow,
        CkmPkcs5Pbkd2Params p => DenyPrf(p.Prf.ToString(), "PBKDF2", "SP 800-132",
            "an HMAC-SHA-1/224/256/384/512/512-224/512-256 PRF"),
        _ => PolicyDecision.Deny(
            "SP 800-132: CKM_PKCS5_PBKD2 requires CkmPkcs5Pbkd2Params naming an approved PRF " +
            "(HMAC-SHA-1/224/256/384/512/512-224/512-256)."),
    };

    private static PolicyDecision CheckSp800108Prf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmSp800108KdfParams p when Prfs.Sp800108.Contains(p.PrfType) => PolicyDecision.Allow,
        CkmSp800108KdfParams p => DenyPrf(p.PrfType.ToString(), "SP 800-108", "SP 800-108r1",
            "HMAC over an approved hash, or AES-CMAC"),
        _ => PolicyDecision.Deny(
            "SP 800-108r1: key derivation requires CkmSp800108KdfParams naming an approved PRF " +
            "(HMAC over an approved hash, or AES-CMAC)."),
    };

    private static PolicyDecision CheckHkdfPrf(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmHkdfParams p when Prfs.Hkdf.Contains(p.PrfHashMechanism) => PolicyDecision.Allow,
        CkmHkdfParams p => DenyPrf(p.PrfHashMechanism.ToString(), "HKDF", "SP 800-56C Rev.2",
            "an approved hash, hash or _HMAC form"),
        _ => PolicyDecision.Deny(
            "SP 800-56C Rev.2: CKM_HKDF_DERIVE / CKM_HKDF_DATA require CkmHkdfParams naming an approved PRF " +
            "(an approved hash, hash or _HMAC form)."),
    };

    /// <summary>
    /// Denies a PRF that failed its family's approved set, naming the PRF and the family's approved set,
    /// with the documented reason and alternative when the PRF is a documented refusal. Every branch is
    /// prefixed with its NIST citation so a FipsOnly denial always cites its source.
    /// </summary>
    private static PolicyDecision DenyPrf(string prf, string family, string citation, string approvedDescription)
    {
        if (!DocumentedRefusedPrfsTable.TryGetValue(prf, out DocumentedRefusal? refusal))
            return PolicyDecision.Deny($"{citation}: {prf} is not an approved {family} PRF; use {approvedDescription}.");

        string useAlternative = refusal.Alternative is { } a ? $" Use {a}." : "";
        return PolicyDecision.Deny($"{citation}: {prf} is not allowed: {refusal.Reason}{useAlternative}");
    }
}
