using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

/// <summary>NistApproved's parameter checks, with each denial citing its NIST source.</summary>
internal static class NistApprovedWording
{
    // Approved hashes (FIPS 180-4 / FIPS 202) usable inside OAEP / PSS.
    private static readonly FrozenSet<CKM> ParamHashes = FrozenSet.ToFrozenSet(
    [
        CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
        CKM.CKM_SHA512_224, CKM.CKM_SHA512_256, CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
    ]);

    // SP 800-131A Rev.2 §9: SHA-1 stays approved for RSA-PSS verification only.
    private static readonly FrozenSet<CKM> PssSignHashes = ParamHashes.Where(h => h != CKM.CKM_SHA_1).ToFrozenSet();
    private static readonly FrozenSet<CKM> PssVerifyOnlyHashes = FrozenSet.ToFrozenSet([CKM.CKM_SHA_1]);

    public static readonly MechanismCheck Oaep = new OaepHashCheck(ParamHashes, new OaepHashWording(
        "requires CkmRsaPkcsOaepParams naming an approved hash",
        "SP 800-56B Rev.2 §7.2.2.1: RSA-OAEP requires CkmRsaPkcsOaepParams with an approved hash.",
        _ => "SP 800-56B Rev.2 §7.2.2.1: RSA-OAEP requires CkmRsaPkcsOaepParams with an approved hash."));

    private static RsaPssWording Pss(string description) => new(
        description,
        "FIPS 186-5 §5.4: RSA-PSS requires CkmRsaPkcsPssParams with an approved hash.",
        "FIPS 186-5 §5.4: RSA-PSS parameters must be CkmRsaPkcsPssParams.",
        hash => $"FIPS 186-5 §5.4(b): {hash} is not an approved hash for RSA-PSS.",
        (hash, op) => $"SP 800-131A Rev.2 §9: {hash} is not approved for RSA-PSS {op}.",
        (salt, hashLength, hash) => $"FIPS 186-5 §5.4(g): a {salt}-byte salt exceeds the {hashLength}-byte {hash} output.");

    public static readonly MechanismCheck RawPss = new RsaPssCheck(PssSignHashes, PssVerifyOnlyHashes, parametersRequired: true,
        Pss("requires CkmRsaPkcsPssParams naming an approved hash, with a salt no longer than that hash"));

    /// <summary>Hash-bound PSS (SHA-224 … SHA3-512 variants).</summary>
    public static readonly MechanismCheck HashedPss = new RsaPssCheck(PssSignHashes, PssVerifyOnlyHashes, parametersRequired: false,
        Pss("the MGF/parameter hash, when given, must be an approved hash"));

    /// <summary>The same check for the legacy, Verify-only <c>CKM_SHA1_RSA_PKCS_PSS</c>, whose docs row reads "(see rationale)".</summary>
    public static readonly MechanismCheck LegacySha1HashedPss = new RsaPssCheck(PssSignHashes, PssVerifyOnlyHashes, parametersRequired: false,
        Pss("(see rationale)"));

    public static readonly MechanismCheck PqcPreHash = new PqcPreHashCheck(
        FrozenSet.ToFrozenSet([CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512]),
        new PqcPreHashWording(
            "requires CkmHashPqcSignParams naming a pre-hash of at least 128-bit collision strength",
            "FIPS 204 §5.4 / FIPS 205 §10: HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams with a pre-hash " +
            "of at least 128-bit collision strength (SHA-256/384/512 or SHA3-256/384/512)."));

    public static readonly MechanismCheck GcmTag = new GcmTagLengthCheck(96, new AeadTagWording(
        "tag, when parameters are given, of 96 to 128 bits (SP 800-38D §5.2.1.2)",
        bits => $"SP 800-38D §5.2.1.2: a {bits}-bit tag is not approved for general use; use 96, 104, 112, 120 or 128 bits.",
        "SP 800-38D §5.2.1.2: AES-GCM requires CkmAesGcmParams or CkmGcmMessageParams, so the tag length can be checked."));

    public static readonly MechanismCheck CcmMac = new CcmMacLengthCheck(64, new AeadTagWording(
        "MAC, when parameters are given, of at least 64 bits (SP 800-38C Appendix B.2)",
        bits => $"SP 800-38C Appendix B.2: a {bits}-bit MAC is below 64 bits, which requires a risk analysis this policy cannot perform.",
        "SP 800-38C: AES-CCM requires CkmAesCcmParams or CkmCcmMessageParams, so the MAC length can be checked."));

    private static KdfPrfWording Prf(string family, string citation, string description, string missing, string approvedDescription) => new(
        description,
        missing,
        prf => $"{citation}: {prf} is not an approved {family} PRF; use {approvedDescription}.",
        (prf, refusal) => $"{citation}: {prf} is not allowed: {refusal.Reason}" +
                          (refusal.Alternative is { } a ? $" Use {a}." : ""));

    public static readonly MechanismCheck Pbkdf2Prf = new KdfPrfCheck(KdfPrfFamily.Pbkdf2,
        FrozenSet.ToFrozenSet(new[] { CKP.CKP_PKCS5_PBKD2_HMAC_SHA1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA224, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA384, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_224, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256 }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("PBKDF2", "SP 800-132",
            "requires CkmPkcs5Pbkd2Params naming an approved PRF (HMAC-SHA-1/224/256/384/512/512-224/512-256)",
            "SP 800-132: CKM_PKCS5_PBKD2 requires CkmPkcs5Pbkd2Params naming an approved PRF " +
            "(HMAC-SHA-1/224/256/384/512/512-224/512-256).",
            "an HMAC-SHA-1/224/256/384/512/512-224/512-256 PRF"));

    public static readonly MechanismCheck Sp800108Prf = new KdfPrfCheck(KdfPrfFamily.Sp800108,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_256_HMAC,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC,
            CKM.CKM_AES_CMAC }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("SP 800-108", "SP 800-108r1",
            "requires CkmSp800108KdfParams naming an approved PRF (HMAC over an approved hash, or AES-CMAC)",
            "SP 800-108r1: key derivation requires CkmSp800108KdfParams naming an approved PRF " +
            "(HMAC over an approved hash, or AES-CMAC).",
            "HMAC over an approved hash, or AES-CMAC"));

    public static readonly MechanismCheck HkdfPrf = new KdfPrfCheck(KdfPrfFamily.Hkdf,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA_1, CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA512_224, CKM.CKM_SHA512_256,
            CKM.CKM_SHA3_224, CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_256_HMAC,
            CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("HKDF", "SP 800-56C Rev.2",
            "requires CkmHkdfParams naming an approved PRF (an approved hash, hash or _HMAC form)",
            "SP 800-56C Rev.2: CKM_HKDF_DERIVE requires CkmHkdfParams naming an approved PRF " +
            "(an approved hash, hash or _HMAC form).",
            "an approved hash, hash or _HMAC form"));
}
