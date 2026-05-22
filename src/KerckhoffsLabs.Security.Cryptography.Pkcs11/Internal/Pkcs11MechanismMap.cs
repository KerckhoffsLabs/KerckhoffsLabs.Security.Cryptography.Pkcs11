using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Central translation from BCL hash / padding choices to PKCS#11 <see cref="Mechanism"/>
/// instances. Used by every BCL-aligned provider (<c>RSAPkcs11</c>, <c>ECDsaPkcs11</c>,
/// etc.) to avoid duplicated mapping logic.
/// </summary>
internal static class Pkcs11MechanismMap
{
    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA PKCS#1 v1.5 signing with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaPkcs1Sign(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => new Mechanism(CKM.CKM_SHA1_RSA_PKCS),
        "SHA256" => new Mechanism(CKM.CKM_SHA256_RSA_PKCS),
        "SHA384" => new Mechanism(CKM.CKM_SHA384_RSA_PKCS),
        "SHA512" => new Mechanism(CKM.CKM_SHA512_RSA_PKCS),
        _ => throw new NotSupportedException(
            $"RSA PKCS#1 sign does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA-PSS signing with the given hash and salt length.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <param name="saltLength">
    /// Salt length in bytes. Pass a negative value to use the recommended default
    /// (hash output length: 20 / 32 / 48 / 64 bytes respectively).
    /// </param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaPssSign(HashAlgorithmName hash, int saltLength)
    {
        var (ckm, innerHash, mgf, effectiveSalt) = hash.Name switch
        {
            "SHA1" => (CKM.CKM_SHA1_RSA_PKCS_PSS, CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1, saltLength < 0 ? 20 : saltLength),
            "SHA256" => (CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength < 0 ? 32 : saltLength),
            "SHA384" => (CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, saltLength < 0 ? 48 : saltLength),
            "SHA512" => (CKM.CKM_SHA512_RSA_PKCS_PSS, CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, saltLength < 0 ? 64 : saltLength),
            _ => throw new NotSupportedException(
                $"RSA-PSS does not support hash {hash.Name}."),
        };
        return new Mechanism(ckm, new CkmRsaPkcsPssParams(innerHash, mgf, effectiveSalt));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA-OAEP encryption/decryption with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaOaep(HashAlgorithmName hash)
    {
        var (innerHash, mgf) = hash.Name switch
        {
            "SHA1" => (CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1),
            "SHA256" => (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
            "SHA384" => (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384),
            "SHA512" => (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512),
            _ => throw new NotSupportedException(
                $"RSA-OAEP does not support hash {hash.Name}."),
        };
        return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(innerHash, mgf));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for ECDSA signing with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism EcdsaSign(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => new Mechanism(CKM.CKM_ECDSA_SHA1),
        "SHA256" => new Mechanism(CKM.CKM_ECDSA_SHA256),
        "SHA384" => new Mechanism(CKM.CKM_ECDSA_SHA384),
        "SHA512" => new Mechanism(CKM.CKM_ECDSA_SHA512),
        _ => throw new NotSupportedException(
            $"ECDSA does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for pure ML-DSA signing (CKM_ML_DSA, PKCS#11 v3.2)
    /// with the supplied context bytes and hedge mode. The mechanism takes ownership of the
    /// underlying parameter struct — dispose the returned <see cref="Mechanism"/> when done.
    /// </summary>
    /// <param name="hedgeVariant">Hedge mode. Default is <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/> (per FIPS 204).</param>
    /// <param name="context">Optional context bytes (max 255 per FIPS 204 §5.2.1).</param>
    public static Mechanism MlDsaSign(
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
        => new(CKM.CKM_ML_DSA, new CkmPqcSignParams(hedgeVariant, context));

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for HashML-DSA signing (CKM_HASH_ML_DSA_*,
    /// PKCS#11 v3.2). Maps the BCL hash name to the matching combined-hash mechanism.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512).</param>
    /// <param name="hedgeVariant">Hedge mode.</param>
    /// <param name="context">Optional context bytes (max 255).</param>
    /// <remarks>
    /// SHAKE128 / SHAKE256 (FIPS 204 §5.4) are intentionally not mapped here. OASIS PKCS#11
    /// v3.2 defines <c>CKM_HASH_ML_DSA_SHAKE128/256</c> as the combined mechanism but does
    /// not define a standalone <c>CKM_SHAKE_128/256</c> hash mechanism — only the
    /// <c>_KEY_DERIVATION</c> variants. The <c>hash</c> field of
    /// <c>CK_HASH_SIGN_ADDITIONAL_CONTEXT</c> has no spec-defined value for the SHAKE-prehash
    /// case, so adding arms requires a token-by-token compatibility test we do not yet have.
    /// </remarks>
    /// <exception cref="NotSupportedException">Unsupported hash.</exception>
    public static Mechanism MlDsaHashSign(
        HashAlgorithmName hash,
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
    {
        var (ckm, innerHash) = hash.Name switch
        {
            "SHA224" => (CKM.CKM_HASH_ML_DSA_SHA224, CKM.CKM_SHA224),
            "SHA256" => (CKM.CKM_HASH_ML_DSA_SHA256, CKM.CKM_SHA256),
            "SHA384" => (CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_SHA384),
            "SHA512" => (CKM.CKM_HASH_ML_DSA_SHA512, CKM.CKM_SHA512),
            "SHA3-224" => (CKM.CKM_HASH_ML_DSA_SHA3_224, CKM.CKM_SHA3_224),
            "SHA3-256" => (CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_SHA3_256),
            "SHA3-384" => (CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_SHA3_384),
            "SHA3-512" => (CKM.CKM_HASH_ML_DSA_SHA3_512, CKM.CKM_SHA3_512),
            _ => throw new NotSupportedException(
                $"HashML-DSA does not support hash {hash.Name}."),
        };
        return new Mechanism(ckm, new CkmHashPqcSignParams(innerHash, hedgeVariant, context));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for fixed-length HMAC (<c>CKM_SHA*_HMAC</c>) with the given hash.
    /// </summary>
    /// <remarks>
    /// This returns the fixed-output-length variant. For the variable-length variant
    /// (<c>CKM_SHA*_HMAC_GENERAL</c>), use a different overload that accepts a truncation length.
    /// </remarks>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism Hmac(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => new Mechanism(CKM.CKM_SHA_1_HMAC),
        "SHA256" => new Mechanism(CKM.CKM_SHA256_HMAC),
        "SHA384" => new Mechanism(CKM.CKM_SHA384_HMAC),
        "SHA512" => new Mechanism(CKM.CKM_SHA512_HMAC),
        _ => throw new NotSupportedException(
            $"HMAC does not support hash {hash.Name}."),
    };
}
