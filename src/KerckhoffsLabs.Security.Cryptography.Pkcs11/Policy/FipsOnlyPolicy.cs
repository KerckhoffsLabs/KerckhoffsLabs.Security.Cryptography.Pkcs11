using System.Collections.Frozen;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// Allows only NIST-approved security functions, per a fixed snapshot of NIST guidance
/// (<see cref="Baseline"/>). Anything not on the list — including vendor-defined mechanisms — is refused.
/// </summary>
/// <remarks>
/// This restricts what the library sends to the token; it does not make an application FIPS 140-3
/// compliant, which also requires a validated module operating in its approved mode. AES key wrapping is
/// approved only via KW/KWP (<c>CKM_AES_KEY_WRAP</c>, <c>CKM_AES_KEY_WRAP_KWP</c>,
/// <c>CKM_AES_KEY_WRAP_PAD</c>) or the GCM/CCM modes; other AES modes encrypt and decrypt data but may
/// not wrap or unwrap keys. Known limits (mirrored in the public <see cref="CryptoPolicy.FipsOnly"/> docs):
/// the policy sees mechanisms, not keys, so an ECDH derive using an existing Montgomery (X25519/X448) key is
/// not detected — only generating such keys is refused; likewise key sizes and curves of existing keys, the
/// ML-DSA / SLH-DSA parameter set behind a pre-hash mechanism, the PRF inside SP 800-108 / PBKDF2
/// parameters, and the KDF inside <c>CKM_ECDH1_DERIVE</c> parameters on the <c>Pkcs11Key.Derive</c> path
/// are not inspected. The EC curve is judged only through <see cref="EcKeyGenerationRequest"/>, which
/// <c>Pkcs11Workspace.GenerateEcKeyPair</c> raises; the generic key-pair
/// <c>GenerateKey(Mechanism, ObjectTemplate, ObjectTemplate)</c> path with
/// <c>CKM_EC_KEY_PAIR_GEN</c> does not. Raw <c>CKM_RSA_PKCS</c> signing and raw <c>CKM_ECDSA</c> cannot see
/// which digest the caller pre-computed, so both are approved without checking it.
/// <c>CKM_AES_KEY_WRAP_PAD</c> is vendor-dependent (see its rule in the table).
/// </remarks>
internal sealed partial class FipsOnlyPolicy : ICryptoPolicy
{
    /// <summary>The NIST publications this table reflects.</summary>
    internal const string Baseline =
        "SP 800-131A Rev.2; SP 800-140C Rev.2 / SP 800-140D Rev.2 (CMVP lists of 2026-08-21); FIPS 186-5; SP 800-186; FIPS 203/204/205";

    public string Name => "FipsOnly";
    public bool AllowsOverride => false;

    internal readonly record struct FipsRule(
        CryptoOperationSet Approved,
        CryptoOperationSet Legacy,
        Func<Mechanism, CryptoOperation, PolicyDecision>? ParameterCheck,
        string Citation);

    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return request switch
        {
            MechanismUseRequest r => EvaluateMechanism(r.Mechanism, r.Operation),
            HashUseRequest r => EvaluateHash(r.Hash, r.Operation),
            RsaKeyGenerationRequest r => r.Mechanism != CKM.CKM_RSA_PKCS_KEY_PAIR_GEN
                ? PolicyDecision.Deny($"FIPS 186-5 §5.1 / Appendix E: {r.Mechanism} is not an approved RSA key-generation method.")
                : r.ModulusBits < 2048
                    ? PolicyDecision.Deny($"FIPS 186-5 §5.1 / SP 800-131A Rev.2 §3: RSA-{r.ModulusBits} is below the 2048-bit minimum for key generation.")
                    : PolicyDecision.Allow,
            EcKeyGenerationRequest r => r.Curve.Oid is { } oid && ApprovedCurveOids.Contains(oid)
                ? PolicyDecision.Allow
                : PolicyDecision.Deny($"SP 800-186 §3.2.1: {r.Curve} is not an approved curve for key generation (approved: P-224, P-256, P-384, P-521)."),
            KeyTemplateRequest r => r.Attributes.Any(a => a.Type == (ulong)CKA.CKA_SENSITIVE && !a.GetValueAsBool())
                ? PolicyDecision.Deny("FIPS 140-3 (ISO/IEC 19790 §7.9): CSPs must not be output in plaintext; CKA_SENSITIVE=false is refused.")
                : PolicyDecision.Allow,
            KeyAgreementKdfRequest r => ApprovedKdfs.Contains(r.Kdf)
                ? PolicyDecision.Allow
                : PolicyDecision.Deny($"SP 800-56A Rev.3 §5.8 / SP 800-56C Rev.2 / SP 800-135 Rev.1 §5.1: {r.Kdf} is not an approved key-derivation method for a shared secret."),
            KeyMaterialExportRequest r => PolicyDecision.Deny(
                $"FIPS 140-3 (ISO/IEC 19790 §7.9): reading the {r.Kind} off the module in plaintext is not permitted."),
            _ => PolicyDecision.Deny($"FipsOnly has no rule for {request.GetType().Name} ({Baseline})."),
        };
    }

    private static PolicyDecision EvaluateMechanism(Mechanism mechanism, CryptoOperation operation)
    {
        CKM type = (CKM)mechanism.Type;
        if (!Rules.TryGetValue(type, out FipsRule rule))
            return PolicyDecision.Deny($"{type} is not on the approved-security-function list (baseline {Baseline}).");

        if (!rule.Approved.Contains(operation) && !rule.Legacy.Contains(operation))
            return PolicyDecision.Deny($"{rule.Citation}: {type} is not approved for {operation}.");

        return rule.ParameterCheck?.Invoke(mechanism, operation) ?? PolicyDecision.Allow;
    }

    private static readonly FrozenSet<string> ApprovedHashNames =
        FrozenSet.ToFrozenSet(["SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"], StringComparer.Ordinal);

    private static PolicyDecision EvaluateHash(HashAlgorithmName hash, CryptoOperation operation)
    {
        if (hash.Name is { } name && ApprovedHashNames.Contains(name))
            return PolicyDecision.Allow;
        if (hash == HashAlgorithmName.SHA1 && operation == CryptoOperation.Verify)
            return PolicyDecision.Allow;
        return PolicyDecision.Deny(
            $"SP 800-131A Rev.2 §9: {hash.Name} is not approved for digital-signature {operation} (SHA-1 is legacy-use verify only).");
    }

    private static readonly FrozenSet<string> ApprovedCurveOids = FrozenSet.ToFrozenSet(
    [
        // P-224 is below SecureOnly's 128-bit baseline but approved: SP 800-186 §3.2.1.2 and
        // SP 800-131A Rev.2 Table 2 (len(n) >= 224 is acceptable).
#pragma warning disable KLPKCS11007
        Pkcs11ECCurve.NamedCurves.NistP224.Oid!,
#pragma warning restore KLPKCS11007
        Pkcs11ECCurve.NamedCurves.NistP256.Oid!,
        Pkcs11ECCurve.NamedCurves.NistP384.Oid!,
        Pkcs11ECCurve.NamedCurves.NistP521.Oid!,
    ], StringComparer.Ordinal);

    /// <summary>
    /// ANSI X9.63 KDFs (<c>CKD_SHA*_KDF</c>) are approved by SP 800-135 Rev.1 §5.1 only with a FIPS 180
    /// hash, so their SHA-3 variants are absent; the SP 800-56C one-step KDFs (<c>*_KDF_SP800</c>) take
    /// SHA-2 or SHA-3. SHA-1 variants are refused by design even where a publication tolerates them.
    /// </summary>
    private static readonly FrozenSet<CKD> ApprovedKdfs = FrozenSet.ToFrozenSet(
    [
        CKD.CKD_SHA224_KDF, CKD.CKD_SHA256_KDF, CKD.CKD_SHA384_KDF, CKD.CKD_SHA512_KDF,
        CKD.CKD_SHA224_KDF_SP800, CKD.CKD_SHA256_KDF_SP800, CKD.CKD_SHA384_KDF_SP800, CKD.CKD_SHA512_KDF_SP800,
        CKD.CKD_SHA3_224_KDF_SP800, CKD.CKD_SHA3_256_KDF_SP800, CKD.CKD_SHA3_384_KDF_SP800, CKD.CKD_SHA3_512_KDF_SP800,
    ]);

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
}
