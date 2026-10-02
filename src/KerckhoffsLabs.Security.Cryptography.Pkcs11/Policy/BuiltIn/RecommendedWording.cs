using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

/// <summary>Recommended's parameter checks, with the policy's plain-language wording.</summary>
internal static class RecommendedWording
{
    private static readonly FrozenSet<CKM> ParamHashes = FrozenSet.ToFrozenSet(
    [
        CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_256,
        CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
    ]);

    public static readonly MechanismCheck Oaep = new OaepHashCheck(ParamHashes, new OaepHashWording(
        "requires CkmRsaPkcsOaepParams naming SHA-256 or stronger",
        "CKM_RSA_PKCS_OAEP requires CkmRsaPkcsOaepParams naming SHA-256 or stronger; without them the " +
        "token chooses the hash (typically SHA-1).",
        hash => hash switch
        {
            CKM.CKM_SHA_1 => "SHA-1 is collision-broken; use CKM_SHA256 or stronger as the OAEP hash.",
            CKM.CKM_SHA224 => "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit " +
                              "over SHA-256 on equal-cost hardware; use CKM_SHA256 or stronger as the OAEP hash.",
            _ => $"{hash} is not an allowed OAEP hash; use CKM_SHA256 or stronger.",
        }));

    private static RsaPssWording Pss(string description) => new(
        description,
        "CKM_RSA_PKCS_PSS requires CkmRsaPkcsPssParams naming SHA-256 or stronger.",
        "RSA-PSS parameters must be CkmRsaPkcsPssParams.",
        hash => $"{hash} is not an allowed RSA-PSS hash; use CKM_SHA256 or stronger.",
        (hash, op) => $"{hash} is not an allowed RSA-PSS hash; use CKM_SHA256 or stronger.",   // unreachable: no verify-only hashes
        (salt, hashLength, hash) => $"A {salt}-byte RSA-PSS salt exceeds the {hashLength}-byte {hash} output.");

    public static readonly MechanismCheck RawPss = new RsaPssCheck(ParamHashes, [], parametersRequired: true,
        Pss("requires CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash"));

    public static readonly MechanismCheck HashedPss = new RsaPssCheck(ParamHashes, [], parametersRequired: false,
        Pss("parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash"));

    public static readonly MechanismCheck PqcPreHash = new PqcPreHashCheck(
        FrozenSet.ToFrozenSet([CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_256,
                               CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512]),
        new PqcPreHashWording(
            "requires CkmHashPqcSignParams naming a pre-hash of at least 256 bits",
            "HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams with a pre-hash of at least 256 bits " +
            "(SHA-256/384/512, SHA-512/256 or SHA3-256/384/512)."));

    public static readonly MechanismCheck GcmTag = new GcmTagLengthCheck(96, new AeadTagWording(
        "tag, when parameters are given, of at least 96 bits",
        bits => $"A {bits}-bit AES-GCM tag is too short to resist forgery; use 96 bits or more (128 recommended).",
        "AES-GCM parameters must be CkmAesGcmParams or CkmGcmMessageParams, so the tag length can be checked."));

    public static readonly MechanismCheck CcmMac = new CcmMacLengthCheck(64, new AeadTagWording(
        "MAC, when parameters are given, of at least 64 bits",
        bits => $"A {bits}-bit AES-CCM MAC is too short to resist forgery; use 64 bits or more (128 recommended).",
        "AES-CCM parameters must be CkmAesCcmParams or CkmCcmMessageParams, so the MAC length can be checked."));

    private static KdfPrfWording Prf(string family, string description, string missing, string allowedDescription) => new(
        description,
        missing,
        prf => $"{prf} is not an allowed {family} PRF; use {allowedDescription}.",
        (prf, refusal) => $"{prf} is not allowed as a {family} PRF: {refusal.Reason}" +
                          (refusal.Alternative is { } a ? $" Use {a}." : ""));

    public static readonly MechanismCheck Pbkdf2Prf = new KdfPrfCheck(KdfPrfFamily.Pbkdf2,
        FrozenSet.ToFrozenSet(new[] { CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, CKP.CKP_PKCS5_PBKD2_HMAC_SHA384,
            CKP.CKP_PKCS5_PBKD2_HMAC_SHA512, CKP.CKP_PKCS5_PBKD2_HMAC_SHA512_256 }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("PBKDF2",
            "requires CkmPkcs5Pbkd2Params naming an allowed PRF (CKP_PKCS5_PBKD2_HMAC_SHA256, _SHA384, _SHA512, or _SHA512_256)",
            "CKM_PKCS5_PBKD2 requires CkmPkcs5Pbkd2Params naming an allowed PRF (CKP_PKCS5_PBKD2_HMAC_SHA256 or stronger).",
            "CKP_PKCS5_PBKD2_HMAC_SHA256 or stronger"));

    public static readonly MechanismCheck Sp800108Prf = new KdfPrfCheck(KdfPrfFamily.Sp800108,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC, CKM.CKM_AES_CMAC }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("SP 800-108",
            "requires CkmSp800108KdfParams naming an allowed PRF (CKM_SHA256/384/512_HMAC, CKM_SHA3_256/384/512_HMAC, or CKM_AES_CMAC)",
            "SP 800-108 key derivation requires CkmSp800108KdfParams naming an allowed PRF " +
            "(CKM_SHA256_HMAC or stronger, or CKM_AES_CMAC).",
            "CKM_SHA256_HMAC or stronger, or CKM_AES_CMAC"));

    public static readonly MechanismCheck HkdfPrf = new KdfPrfCheck(KdfPrfFamily.Hkdf,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_512_HMAC }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("HKDF",
            "requires CkmHkdfParams naming an allowed PRF (CKM_SHA256/384/512 or CKM_SHA3_256/384/512, hash or _HMAC form)",
            "CKM_HKDF_DERIVE requires CkmHkdfParams naming an allowed PRF " +
            "(CKM_SHA256 or stronger, hash or _HMAC form).",
            "CKM_SHA256 or stronger, hash or _HMAC form"));
}
