using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

// This file builds the very mechanisms the secure-by-default policy gates: it sits on the
// enforcement side of the check (Pkcs11Session.GuardMechanism rejects them at the point of use
// unless AllowInsecure is set), whereas KLPKCS11009 exists to warn a *caller* who selects one.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Central translation from BCL hash / padding choices to PKCS#11 <see cref="Mechanism"/>
/// instances. Used by every BCL-aligned provider (<c>RSAPkcs11</c>, <c>ECDsaPkcs11</c>,
/// etc.) to avoid duplicated mapping logic.
/// </summary>
public static class Pkcs11MechanismMap
{
    // BCL HashAlgorithmName.Name values used as switch keys throughout this map (S1192).
    private const string Sha1 = "SHA1";
    private const string Sha224 = "SHA224";
    private const string Sha256 = "SHA256";
    private const string Sha384 = "SHA384";
    private const string Sha512 = "SHA512";

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA PKCS#1 v1.5 signing with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <remarks>
    /// SHA-224 (<c>CKM_SHA224_RSA_PKCS</c>) has no <see cref="HashAlgorithmName"/> constant in the
    /// BCL and is gated behind <c>Pkcs11Workspace.AllowInsecure</c> — same opt-in as SHA-1 — since
    /// it is a deviation from the BCL-aligned hash set rather than a mechanism this API otherwise
    /// exposes by default. See <c>Pkcs11Session.GuardMechanism</c>.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaPkcs1Sign(HashAlgorithmName hash) => hash.Name switch
    {
        Sha1 => new Mechanism(CKM.CKM_SHA1_RSA_PKCS),
        Sha224 => new Mechanism(CKM.CKM_SHA224_RSA_PKCS),
        Sha256 => new Mechanism(CKM.CKM_SHA256_RSA_PKCS),
        Sha384 => new Mechanism(CKM.CKM_SHA384_RSA_PKCS),
        Sha512 => new Mechanism(CKM.CKM_SHA512_RSA_PKCS),
        _ => throw new NotSupportedException(
            $"RSA PKCS#1 sign does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA-PSS signing with the given hash and salt length.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <param name="saltLength">
    /// Salt length in bytes. Pass a negative value to use the recommended default
    /// (hash output length: 20 / 28 / 32 / 48 / 64 bytes respectively).
    /// </param>
    /// <remarks>
    /// SHA-224 (<c>CKM_SHA224_RSA_PKCS_PSS</c>) has no <see cref="HashAlgorithmName"/> constant in
    /// the BCL and is gated behind <c>Pkcs11Workspace.AllowInsecure</c> — same opt-in as SHA-1. See
    /// <c>Pkcs11Session.GuardMechanism</c>.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaPssSign(HashAlgorithmName hash, int saltLength)
    {
        var (ckm, innerHash, mgf, effectiveSalt) = hash.Name switch
        {
            Sha1 => (CKM.CKM_SHA1_RSA_PKCS_PSS, CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1, saltLength < 0 ? 20 : saltLength),
            Sha224 => (CKM.CKM_SHA224_RSA_PKCS_PSS, CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224, saltLength < 0 ? 28 : saltLength),
            Sha256 => (CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength < 0 ? 32 : saltLength),
            Sha384 => (CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, saltLength < 0 ? 48 : saltLength),
            Sha512 => (CKM.CKM_SHA512_RSA_PKCS_PSS, CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, saltLength < 0 ? 64 : saltLength),
            _ => throw new NotSupportedException(
                $"RSA-PSS does not support hash {hash.Name}."),
        };
        return new Mechanism(ckm, new CkmRsaPkcsPssParams(innerHash, mgf, effectiveSalt));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for RSA-OAEP encryption/decryption with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <remarks>
    /// SHA-1 and SHA-224 inner hashes are gated behind <c>Pkcs11Workspace.AllowInsecure</c> by
    /// <c>Pkcs11Session.GuardMechanism</c>, which inspects <see cref="CkmRsaPkcsOaepParams.HashAlg"/>
    /// since <c>CKM_RSA_PKCS_OAEP</c> is a single mechanism type for every hash choice.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism RsaOaep(HashAlgorithmName hash)
    {
        var (innerHash, mgf) = hash.Name switch
        {
            Sha1 => (CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1),
            Sha224 => (CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224),
            Sha256 => (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
            Sha384 => (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384),
            Sha512 => (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512),
            _ => throw new NotSupportedException(
                $"RSA-OAEP does not support hash {hash.Name}."),
        };
        return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(innerHash, mgf));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for ECDSA signing with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <remarks>
    /// SHA-224 (<c>CKM_ECDSA_SHA224</c>) has no <see cref="HashAlgorithmName"/> constant in the BCL
    /// and is gated behind <c>Pkcs11Workspace.AllowInsecure</c> — same opt-in as SHA-1. See
    /// <c>Pkcs11Session.GuardMechanism</c>.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism EcdsaSign(HashAlgorithmName hash) => hash.Name switch
    {
        Sha1 => new Mechanism(CKM.CKM_ECDSA_SHA1),
        Sha224 => new Mechanism(CKM.CKM_ECDSA_SHA224),
        Sha256 => new Mechanism(CKM.CKM_ECDSA_SHA256),
        Sha384 => new Mechanism(CKM.CKM_ECDSA_SHA384),
        Sha512 => new Mechanism(CKM.CKM_ECDSA_SHA512),
        _ => throw new NotSupportedException(
            $"ECDSA does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for pure ML-DSA signing (CKM_ML_DSA, PKCS#11 v3.2)
    /// with the supplied context bytes and hedge mode. The returned mechanism holds only managed
    /// state; its parameters are marshalled into each call's own scope.
    /// </summary>
    /// <param name="hedgeVariant">Hedge mode. Default is <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/> (per FIPS 204).</param>
    /// <param name="context">Optional context bytes (max 255 per FIPS 204 §5.2.1).</param>
    public static Mechanism MlDsaSign(
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
        => new(CKM.CKM_ML_DSA, new CkmPqcSignParams(hedgeVariant, context));

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for combined hash-and-sign DSA with the given hash
    /// (<c>CKM_DSA_SHA1/224/256/384/512</c>). The token hashes the message and signs in one call.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism DsaSign(HashAlgorithmName hash) => hash.Name switch
    {
        Sha1 => new Mechanism(CKM.CKM_DSA_SHA1),
        "SHA224" => new Mechanism(CKM.CKM_DSA_SHA224),
        Sha256 => new Mechanism(CKM.CKM_DSA_SHA256),
        Sha384 => new Mechanism(CKM.CKM_DSA_SHA384),
        Sha512 => new Mechanism(CKM.CKM_DSA_SHA512),
        _ => throw new NotSupportedException(
            $"DSA does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for pure SLH-DSA signing (CKM_SLH_DSA, PKCS#11 v3.2)
    /// with the supplied context bytes and hedge mode. The returned mechanism holds only managed
    /// state; its parameters are marshalled into each call's own scope.
    /// </summary>
    /// <param name="hedgeVariant">Hedge mode. Default is <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/> (per FIPS 205).</param>
    /// <param name="context">Optional context bytes (max 255 per FIPS 205 §10.2).</param>
    public static Mechanism SlhDsaSign(
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
        => new(CKM.CKM_SLH_DSA, new CkmPqcSignParams(hedgeVariant, context));

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for HashML-DSA signing (CKM_HASH_ML_DSA_*,
    /// PKCS#11 v3.2). Maps the BCL hash name to the matching combined-hash mechanism.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512).</param>
    /// <param name="hedgeVariant">Hedge mode.</param>
    /// <param name="context">Optional context bytes (max 255).</param>
    /// <remarks>
    /// These combined mechanisms (e.g. <c>CKM_HASH_ML_DSA_SHA256</c>) already encode the hash in the
    /// mechanism type itself, so the parameter block is the plain <c>CK_SIGN_ADDITIONAL_CONTEXT</c>
    /// (hedge + context only), not <c>CK_HASH_SIGN_ADDITIONAL_CONTEXT</c>'s extra <c>hash</c> field —
    /// that field exists only for the bare <c>CKM_HASH_ML_DSA</c> mechanism, where the caller must
    /// name the prehash explicitly. opencryptoki's <c>ml_dsa_get_digest_mech</c> enforces exactly this
    /// split: it validates <c>ulParameterLen</c> against <c>sizeof(CK_SIGN_ADDITIONAL_CONTEXT)</c> for
    /// every combined mechanism and derives the hash from the mechanism type itself.
    /// SHAKE128 / SHAKE256 (FIPS 204 §5.4) are intentionally not mapped here. OASIS PKCS#11
    /// v3.2 defines <c>CKM_HASH_ML_DSA_SHAKE128/256</c> as the combined mechanism but does
    /// not define a standalone <c>CKM_SHAKE_128/256</c> hash mechanism — only the
    /// <c>_KEY_DERIVATION</c> variants — so adding arms requires a token-by-token compatibility
    /// test we do not yet have.
    /// </remarks>
    /// <exception cref="NotSupportedException">Unsupported hash.</exception>
    public static Mechanism MlDsaHashSign(
        HashAlgorithmName hash,
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
    {
        CKM ckm = hash.Name switch
        {
            "SHA224" => CKM.CKM_HASH_ML_DSA_SHA224,
            Sha256 => CKM.CKM_HASH_ML_DSA_SHA256,
            Sha384 => CKM.CKM_HASH_ML_DSA_SHA384,
            Sha512 => CKM.CKM_HASH_ML_DSA_SHA512,
            "SHA3-224" => CKM.CKM_HASH_ML_DSA_SHA3_224,
            "SHA3-256" => CKM.CKM_HASH_ML_DSA_SHA3_256,
            "SHA3-384" => CKM.CKM_HASH_ML_DSA_SHA3_384,
            "SHA3-512" => CKM.CKM_HASH_ML_DSA_SHA3_512,
            _ => throw new NotSupportedException(
                $"HashML-DSA does not support hash {hash.Name}."),
        };
        return new Mechanism(ckm, new CkmPqcSignParams(hedgeVariant, context));
    }

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for fixed-length HMAC (<c>CKM_SHA*_HMAC</c>) with the given hash.
    /// </summary>
    /// <remarks>
    /// This returns the fixed-output-length variant. For the variable-length variant
    /// (<c>CKM_SHA*_HMAC_GENERAL</c>), use a different overload that accepts a truncation length.
    /// </remarks>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA224, SHA256, SHA384, SHA512).</param>
    /// <remarks>
    /// SHA-224 (<c>CKM_SHA224_HMAC</c>) has no <see cref="HashAlgorithmName"/> constant in the BCL
    /// and is gated behind <c>Pkcs11Workspace.AllowInsecure</c> — same opt-in as SHA-1. See
    /// <c>Pkcs11Session.GuardMechanism</c>.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism Hmac(HashAlgorithmName hash) => hash.Name switch
    {
        Sha1 => new Mechanism(CKM.CKM_SHA_1_HMAC),
        Sha224 => new Mechanism(CKM.CKM_SHA224_HMAC),
        Sha256 => new Mechanism(CKM.CKM_SHA256_HMAC),
        Sha384 => new Mechanism(CKM.CKM_SHA384_HMAC),
        Sha512 => new Mechanism(CKM.CKM_SHA512_HMAC),
        _ => throw new NotSupportedException(
            $"HMAC does not support hash {hash.Name}."),
    };
}
