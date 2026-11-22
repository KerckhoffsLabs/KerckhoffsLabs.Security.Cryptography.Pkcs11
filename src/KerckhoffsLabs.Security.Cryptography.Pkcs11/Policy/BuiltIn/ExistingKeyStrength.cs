using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

/// <summary>
/// The key-strength rules of <see cref="CryptoPolicy.Recommended"/> and <see cref="CryptoPolicy.NistApproved"/>: an
/// existing RSA or EC key is judged by its modulus or curve each time it is used, as a generated one already is when
/// it is generated (<see cref="RsaKeyGenerationRule"/>, the curve allow-list).
/// </summary>
/// <remarks>
/// <para>
/// Only RSA and EC keys used by an operation are judged. A template or a created key is allowed here: generating one
/// is judged by the generation rules, and a weak key imported or unwrapped is refused at its first use. Every other key
/// type is allowed, whatever the token reports of it, as both policies allow every size of them.
/// </para>
/// <para>
/// The modulus and the curve are public attributes every token reports, so a key whose modulus or named curve the token
/// does not report (or whose curve is given by explicit domain parameters) is refused: its strength cannot be checked.
/// </para>
/// </remarks>
internal static class ExistingKeyStrength
{
    private const int MinimumModulusBits = 2048;
    private const int LegacyVerifyModulusBits = 1024;

    internal const string RecommendedRationale =
        "Each time an existing RSA or EC key is used, its modulus (CKA_MODULUS) or curve (CKA_EC_PARAMS) is read from the " +
        "token: an RSA key must have at least 2048 bits and an EC key must be on the curve allow-list, for every operation, " +
        "verification included (NIST SP 800-131A Rev.2). A key whose modulus or named curve the token does not report is " +
        "refused. Other key types are not judged by size.";

    internal const string NistApprovedRationale =
        "Each time an existing RSA or EC key is used, its modulus (CKA_MODULUS) or curve (CKA_EC_PARAMS) is read from the " +
        "token: an RSA key must have at least 2048 bits and an EC key must be on the curve allow-list. Verifying an old " +
        "signature is the one legacy use: RSA keys of 1024 to 2047 bits and curves with 160 <= len(n) < 224 (P-192) may " +
        "still verify (SP 800-131A Rev.2 Table 2). A key whose modulus or named curve the token does not report is refused. " +
        "Other key types are not judged by size.";

    /// <summary><see cref="CryptoPolicy.Recommended"/>'s rule: RSA-2048 and the curve allow-list, for every operation.</summary>
    internal static KeyStrengthRule Recommended(FrozenDictionary<string, string> allowedCurves)
        => KeyStrengthRule.FromDelegate(request => Judge(request, allowedCurves, legacyVerify: false), RecommendedRationale);

    /// <summary><see cref="CryptoPolicy.NistApproved"/>'s rule: as Recommended's, with SP 800-131A's legacy-use verification.</summary>
    internal static KeyStrengthRule NistApproved(FrozenDictionary<string, string> allowedCurves)
        => KeyStrengthRule.FromDelegate(request => Judge(request, allowedCurves, legacyVerify: true), NistApprovedRationale);

    private static PolicyDecision Judge(KeyStrengthRequest request, FrozenDictionary<string, string> allowedCurves, bool legacyVerify)
    {
        if (request.Source != KeyStrengthSource.ExistingKey)
            return PolicyDecision.Allow;

        bool verifies = request.Operation == CryptoOperation.Verify;
        return request.KeyType switch
        {
            CKK.CKK_RSA => JudgeRsa(request.ModulusBits, request.Operation, legacyVerify && verifies),
            CKK.CKK_EC => JudgeCurve(request.Curve, request.Operation, allowedCurves, legacyVerify && verifies),
            _ => PolicyDecision.Allow,
        };
    }

    private static PolicyDecision JudgeRsa(int? modulusBits, CryptoOperation? operation, bool legacyVerify) => modulusBits switch
    {
        null => PolicyDecision.Deny("The token did not report the RSA key's modulus (CKA_MODULUS), so its length can't be checked."),
        >= MinimumModulusBits => PolicyDecision.Allow,
        >= LegacyVerifyModulusBits when legacyVerify => PolicyDecision.Allow,
        int bits when legacyVerify => PolicyDecision.Deny(
            $"SP 800-131A Rev.2 Table 2: an RSA key of {bits} bits is disallowed, even to verify an old signature (legacy use needs at least {LegacyVerifyModulusBits})."),
        int bits => PolicyDecision.Deny(
            $"An RSA key of {bits} bits is below the {MinimumModulusBits}-bit minimum (NIST SP 800-131A Rev.2) for {OperationName(operation)}; " +
            $"use a key of at least {MinimumModulusBits} bits."),
    };

    private static PolicyDecision JudgeCurve(Pkcs11ECCurve? curve, CryptoOperation? operation, FrozenDictionary<string, string> allowedCurves,
        bool legacyVerify) => curve switch
        {
            null => PolicyDecision.Deny(
                "The token did not report a named curve for the EC key (CKA_EC_PARAMS absent, or explicit domain parameters), so it can't be checked."),
            { Oid: { } oid } when allowedCurves.ContainsKey(oid) => PolicyDecision.Allow,
            { FieldSizeBits: >= 160 and < 224 } when legacyVerify => PolicyDecision.Allow,
            { } other => PolicyDecision.Deny(
                $"The EC key is on {other}, which is not on the curve allow-list for {OperationName(operation)}; use a key on an allowed curve."),
        };

    private static string OperationName(CryptoOperation? operation) => operation is { } op ? op.ToString() : "this use";
}
