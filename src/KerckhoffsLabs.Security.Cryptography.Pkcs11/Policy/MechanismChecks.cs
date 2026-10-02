using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// The reusable parameter checks a policy attaches to allow-list entries with
/// <see cref="CryptoPolicyBuilder.AllowMechanism(CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>. Each check is immutable; its denials name the set or
/// floor it was created with.
/// </summary>
public static class MechanismChecks
{
    /// <summary>Requires <c>CkmRsaPkcsOaepParams</c> naming one of <paramref name="allowedHashes"/>.</summary>
    /// <param name="allowedHashes">The hash mechanisms OAEP may use (e.g. <c>CKM_SHA256</c>).</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedHashes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="allowedHashes"/> is empty.</exception>
    public static MechanismCheck OaepHash(IEnumerable<CKM> allowedHashes)
    {
        FrozenSet<CKM> allowed = NonEmpty(allowedHashes, nameof(allowedHashes));
        string list = List(allowed);
        return new OaepHashCheck(allowed, new OaepHashWording(
            $"requires CkmRsaPkcsOaepParams naming {list}",
            $"CKM_RSA_PKCS_OAEP requires CkmRsaPkcsOaepParams naming {list}.",
            hash => $"{hash} is not an allowed OAEP hash; allowed: {list}."));
    }

    /// <summary>
    /// RSA-PSS parameters naming one of <paramref name="allowedHashes"/> (or, to verify only, one of
    /// <paramref name="verifyOnlyHashes"/>), with a salt no longer than the hash output.
    /// </summary>
    /// <param name="allowedHashes">Hashes PSS may use for every operation.</param>
    /// <param name="parametersRequired"><see langword="true"/> for raw <c>CKM_RSA_PKCS_PSS</c>, which must carry
    /// parameters; <see langword="false"/> for a hash-bound PSS mechanism, checked only when it carries them.</param>
    /// <param name="verifyOnlyHashes">Hashes PSS may use only to verify (an old signature); none when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedHashes"/> is null.</exception>
    /// <exception cref="ArgumentException">A set is empty (pass <see langword="null"/> for no verify-only hashes), or names a hash with no known output length.</exception>
    public static MechanismCheck RsaPss(IEnumerable<CKM> allowedHashes, bool parametersRequired, IEnumerable<CKM>? verifyOnlyHashes = null)
    {
        FrozenSet<CKM> allowed = KnownHashes(NonEmpty(allowedHashes, nameof(allowedHashes)), nameof(allowedHashes));
        FrozenSet<CKM> verifyOnly = verifyOnlyHashes is null
            ? []
            : KnownHashes(NonEmpty(verifyOnlyHashes, nameof(verifyOnlyHashes)), nameof(verifyOnlyHashes));
        string list = List(allowed);
        return new RsaPssCheck(allowed, verifyOnly, parametersRequired, new RsaPssWording(
            parametersRequired
                ? $"requires CkmRsaPkcsPssParams naming {list}, with a salt no longer than that hash"
                : $"parameters, when given, must be CkmRsaPkcsPssParams naming {list}, with a salt no longer than that hash",
            $"CKM_RSA_PKCS_PSS requires CkmRsaPkcsPssParams naming {list}.",
            "RSA-PSS parameters must be CkmRsaPkcsPssParams.",
            hash => $"{hash} is not an allowed RSA-PSS hash; allowed: {list}.",
            (hash, op) => $"{hash} is allowed for RSA-PSS only to Verify, not to {op}.",
            (salt, hashLength, hash) => $"A {salt}-byte RSA-PSS salt exceeds the {hashLength}-byte {hash} output."));
    }

    /// <summary>Requires <c>CkmHashPqcSignParams</c> naming one of <paramref name="allowedHashes"/> (HashML-DSA / HashSLH-DSA).</summary>
    /// <param name="allowedHashes">The pre-hash mechanisms allowed.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedHashes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="allowedHashes"/> is empty.</exception>
    public static MechanismCheck PqcPreHash(IEnumerable<CKM> allowedHashes)
    {
        FrozenSet<CKM> allowed = NonEmpty(allowedHashes, nameof(allowedHashes));
        string list = List(allowed);
        return new PqcPreHashCheck(allowed, new PqcPreHashWording(
            $"requires CkmHashPqcSignParams naming {list}",
            $"HashML-DSA / HashSLH-DSA require CkmHashPqcSignParams naming {list}."));
    }

    /// <summary>Refuses an AES-GCM tag shorter than <paramref name="minimumBits"/>, in single-part or message-based parameters.</summary>
    /// <param name="minimumBits">The shortest tag allowed, 32 to 128 bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="minimumBits"/> is outside 32 to 128.</exception>
    public static MechanismCheck GcmTagLength(int minimumBits)
    {
        RequireTagRange(minimumBits, nameof(minimumBits));
        return new GcmTagLengthCheck(minimumBits, new AeadTagWording(
            $"tag, when parameters are given, of at least {minimumBits} bits",
            bits => $"A {bits}-bit AES-GCM tag is below this policy's {minimumBits}-bit minimum.",
            "AES-GCM parameters must be CkmAesGcmParams or CkmGcmMessageParams, so the tag length can be checked."));
    }

    /// <summary>Refuses an AES-CCM MAC shorter than <paramref name="minimumBits"/>, in single-part or message-based parameters.</summary>
    /// <param name="minimumBits">The shortest MAC allowed, 32 to 128 bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="minimumBits"/> is outside 32 to 128.</exception>
    public static MechanismCheck CcmMacLength(int minimumBits)
    {
        RequireTagRange(minimumBits, nameof(minimumBits));
        return new CcmMacLengthCheck(minimumBits, new AeadTagWording(
            $"MAC, when parameters are given, of at least {minimumBits} bits",
            bits => $"A {bits}-bit AES-CCM MAC is below this policy's {minimumBits}-bit minimum.",
            "AES-CCM parameters must be CkmAesCcmParams or CkmCcmMessageParams, so the MAC length can be checked."));
    }

    /// <summary>Requires <c>CkmPkcs5Pbkd2Params</c> naming one of <paramref name="allowedPrfs"/>.</summary>
    /// <param name="allowedPrfs">The PBKDF2 PRFs allowed.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedPrfs"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="allowedPrfs"/> is empty.</exception>
    public static MechanismCheck Pbkdf2Prf(IEnumerable<CKP> allowedPrfs) =>
        Prf(KdfPrfFamily.Pbkdf2, NonEmpty(allowedPrfs, nameof(allowedPrfs)).Select(p => p.ToString()), "CkmPkcs5Pbkd2Params", "CKM_PKCS5_PBKD2");

    /// <summary>Requires <c>CkmSp800108KdfParams</c> naming one of <paramref name="allowedPrfs"/>.</summary>
    /// <param name="allowedPrfs">The SP 800-108 PRF mechanisms allowed (e.g. <c>CKM_SHA256_HMAC</c>, <c>CKM_AES_CMAC</c>).</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedPrfs"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="allowedPrfs"/> is empty.</exception>
    public static MechanismCheck Sp800108Prf(IEnumerable<CKM> allowedPrfs) =>
        Prf(KdfPrfFamily.Sp800108, NonEmpty(allowedPrfs, nameof(allowedPrfs)).Select(p => p.ToString()), "CkmSp800108KdfParams", "SP 800-108 key derivation");

    /// <summary>Requires <c>CkmHkdfParams</c> naming one of <paramref name="allowedPrfs"/>.</summary>
    /// <param name="allowedPrfs">The HKDF PRFs allowed, as hash or <c>_HMAC</c> mechanisms.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedPrfs"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="allowedPrfs"/> is empty.</exception>
    public static MechanismCheck HkdfPrf(IEnumerable<CKM> allowedPrfs) =>
        Prf(KdfPrfFamily.Hkdf, NonEmpty(allowedPrfs, nameof(allowedPrfs)).Select(p => p.ToString()), "CkmHkdfParams", "CKM_HKDF_DERIVE");

    /// <summary>
    /// Requires <c>CkmEcdh1DeriveParams</c>, so the key-agreement KDF they carry reaches the policy's KDF
    /// allow-list; any other parameters would hide it.
    /// </summary>
    public static MechanismCheck Ecdh1DeriveParams() => Ecdh1DeriveParamsCheck.Instance;

    private static KdfPrfCheck Prf(KdfPrfFamily family, IEnumerable<string> prfs, string parameterType, string subject)
    {
        FrozenSet<string> allowed = prfs.ToFrozenSet(StringComparer.Ordinal);
        string list = string.Join(", ", allowed.Order(StringComparer.Ordinal));
        return new KdfPrfCheck(family, allowed, new KdfPrfWording(
            $"requires {parameterType} naming {list}",
            $"{subject} requires {parameterType} naming {list}.",
            prf => $"{prf} is not an allowed {family.ShortName} PRF; allowed: {list}.",
            (prf, refusal) => $"{prf} is not allowed as a {family.ShortName} PRF: {refusal.Reason}" +
                              (refusal.Alternative is { } a ? $" Use {a}." : "")));
    }

    private static FrozenSet<T> NonEmpty<T>(IEnumerable<T> values, string paramName)
    {
        // The caller's parameter is named explicitly: the values are its argument, not this helper's.
        if (values is null)
            throw new ArgumentNullException(paramName);
        FrozenSet<T> set = values.ToFrozenSet();
        if (set.Count == 0)
            throw new ArgumentException("At least one value is required.", paramName);
        return set;
    }

    private static FrozenSet<CKM> KnownHashes(FrozenSet<CKM> hashes, string paramName)
    {
        CKM[] unknown = [.. hashes.Where(h => !HashOutputLengths.IsKnown(h)).Order()];
        if (unknown.Length > 0)
            throw new ArgumentException(
                $"{string.Join(", ", unknown)}: not a hash with a known output length.", paramName);
        return hashes;
    }

    private static void RequireTagRange(int bits, string paramName)
    {
        if (bits is < 32 or > 128)
            throw new ArgumentOutOfRangeException(paramName, bits, "The length must be between 32 and 128 bits.");
    }

    private static string List(FrozenSet<CKM> values) =>
        string.Join(", ", values.Select(v => v.ToString()).Order(StringComparer.Ordinal));
}
