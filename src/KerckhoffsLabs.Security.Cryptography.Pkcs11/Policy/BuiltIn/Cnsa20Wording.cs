using System.Collections.Frozen;
using System.Globalization;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

/// <summary>Cnsa20's parameter checks and key-strength rule, with each denial naming CNSA 2.0.</summary>
internal static class Cnsa20Wording
{
    /// <summary>The key-strength rule in one sentence, rendered as its row in the generated catalogue.</summary>
    internal const string KeyStrengthRationale =
        "Every key is inspected when it is created and each time it is used: AES keys must be AES-256 (CKA_VALUE_LEN = 32); " +
        "generic-secret, HKDF and HMAC-SHA-384/512 keys must hold a secret of at least 256 bits; ML-KEM keys must be ML-KEM-1024 " +
        "and ML-DSA keys ML-DSA-87 (CKA_PARAMETER_SET); HSS keys must be single-level LMS (CKA_HSS_LEVELS = 1); XMSS keys are " +
        "allowed. Every other key type is refused, and so is a key whose type, length, parameter set or HSS levels the token " +
        "does not report.";

    private const string Cnsa = "CNSA 2.0";

    public static readonly MechanismCheck GcmTag = new GcmTagLengthCheck(128, new AeadTagWording(
        "tag, when parameters are given, of 128 bits",
        bits => $"{Cnsa} (this policy): a {bits}-bit AES-GCM tag is refused; use a 128-bit tag.",
        $"{Cnsa}: AES-GCM requires CkmAesGcmParams or CkmGcmMessageParams, so the tag length can be checked."));

    private static KdfPrfWording Prf(string family, string description, string missing, string allowedDescription) => new(
        description,
        missing,
        prf => $"{Cnsa}: {prf} is not an allowed {family} PRF; use {allowedDescription}.",
        (prf, refusal) => $"{Cnsa}: {prf} is not allowed: {refusal.Reason}" +
                          (refusal.Alternative is { } a ? $" Use {a}." : ""));

    public static readonly MechanismCheck Sp800108Prf = new KdfPrfCheck(KdfPrfFamily.Sp800108,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC }.Select(p => p.ToString()), StringComparer.Ordinal),
        Prf("SP 800-108",
            "requires CkmSp800108KdfParams naming HMAC-SHA-384 or HMAC-SHA-512",
            $"{Cnsa}: SP 800-108 key derivation requires CkmSp800108KdfParams naming HMAC-SHA-384 or HMAC-SHA-512.",
            "CKM_SHA384_HMAC or CKM_SHA512_HMAC"));

    // Same value format as NistApprovedWording.HkdfPrf: tokens name the HKDF PRF by its hash or its _HMAC form.
    public static readonly MechanismCheck HkdfPrf = new KdfPrfCheck(KdfPrfFamily.Hkdf,
        FrozenSet.ToFrozenSet(new[] { CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC }.Select(p => p.ToString()),
            StringComparer.Ordinal),
        Prf("HKDF",
            "requires CkmHkdfParams naming SHA-384 or SHA-512 (hash or _HMAC form)",
            $"{Cnsa}: CKM_HKDF_DERIVE requires CkmHkdfParams naming SHA-384 or SHA-512 (hash or _HMAC form).",
            "SHA-384 or SHA-512 (CKM_SHA384, CKM_SHA512, CKM_SHA384_HMAC or CKM_SHA512_HMAC)"));

    // --- Key strength (KeyStrengthRequest) ---

    /// <summary>Decides one <see cref="KeyStrengthRequest"/>; fails closed on anything the token did not report.</summary>
    internal static PolicyDecision JudgeKeyStrength(KeyStrengthRequest request) => request.KeyType switch
    {
        null => Unreported("type"),
        CKK.CKK_AES => request.ValueLengthBytes switch
        {
            null => Unreported("length"),
            32 => PolicyDecision.Allow,
            int bytes => TooSmall("AES-256", $"AES-{Bits(bytes)}"),
        },
        CKK.CKK_GENERIC_SECRET or CKK.CKK_HKDF or CKK.CKK_SHA384_HMAC or CKK.CKK_SHA512_HMAC => request.ValueLengthBytes switch
        {
            null => Unreported("length"),
            >= 32 => PolicyDecision.Allow,
            int bytes => TooSmall("a secret of at least 256 bits", $"{Bits(bytes)} bits"),
        },
        CKK.CKK_ML_KEM => request.ParameterSet switch
        {
            null => Unreported("parameter set"),
            (ulong)CkpMlKem.CKP_ML_KEM_1024 => PolicyDecision.Allow,
            ulong set => TooSmall("ML-KEM-1024", ParameterSetName<CkpMlKem>(set)),
        },
        CKK.CKK_ML_DSA => request.ParameterSet switch
        {
            null => Unreported("parameter set"),
            (ulong)CkpMlDsa.CKP_ML_DSA_87 => PolicyDecision.Allow,
            ulong set => TooSmall("ML-DSA-87", ParameterSetName<CkpMlDsa>(set)),
        },
        CKK.CKK_HSS => request.HssLevels switch
        {
            null => Unreported("HSS levels"),
            1 => PolicyDecision.Allow,
            ulong levels => TooSmall("single-level LMS (HSS levels = 1)", $"{levels.ToString(CultureInfo.InvariantCulture)} levels"),
        },
        CKK.CKK_XMSS => PolicyDecision.Allow,
        CKK type => PolicyDecision.Deny($"{KeyTypeNames.Of(type)} keys are not part of {Cnsa}."),
    };

    private static PolicyDecision Unreported(string what) =>
        PolicyDecision.Deny($"The token did not report the key's {what}, so {Cnsa} compliance can't be verified.");

    private static PolicyDecision TooSmall(string required, string actual) =>
        PolicyDecision.Deny($"{Cnsa} requires {required}; this is {actual}.");

    private static string Bits(int bytes) => (8L * bytes).ToString(CultureInfo.InvariantCulture);

    private static string ParameterSetName<T>(ulong set) where T : struct, Enum =>
        Enum.IsDefined(typeof(T), set) ? Enum.ToObject(typeof(T), set).ToString()! : $"0x{set:X}";
}
