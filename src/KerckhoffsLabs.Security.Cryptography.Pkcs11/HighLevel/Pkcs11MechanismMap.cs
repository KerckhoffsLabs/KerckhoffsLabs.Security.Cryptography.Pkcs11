using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

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
        "SHA1"   => new Mechanism(CKM.CKM_SHA1_RSA_PKCS),
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
            "SHA1"   => (CKM.CKM_SHA1_RSA_PKCS_PSS,   CKM.CKM_SHA_1,  CKG.CKG_MGF1_SHA1,   saltLength < 0 ? 20 : saltLength),
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
            "SHA1"   => (CKM.CKM_SHA_1,  CKG.CKG_MGF1_SHA1),
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
        "SHA1"   => new Mechanism(CKM.CKM_ECDSA_SHA1),
        "SHA256" => new Mechanism(CKM.CKM_ECDSA_SHA256),
        "SHA384" => new Mechanism(CKM.CKM_ECDSA_SHA384),
        "SHA512" => new Mechanism(CKM.CKM_ECDSA_SHA512),
        _ => throw new NotSupportedException(
            $"ECDSA does not support hash {hash.Name}."),
    };

    /// <summary>
    /// Returns a <see cref="Mechanism"/> for HMAC with the given hash.
    /// </summary>
    /// <param name="hash">BCL hash algorithm name (SHA1, SHA256, SHA384, SHA512).</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported hash algorithms.</exception>
    public static Mechanism HmacGeneral(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => new Mechanism(CKM.CKM_SHA_1_HMAC),
        "SHA256" => new Mechanism(CKM.CKM_SHA256_HMAC),
        "SHA384" => new Mechanism(CKM.CKM_SHA384_HMAC),
        "SHA512" => new Mechanism(CKM.CKM_SHA512_HMAC),
        _ => throw new NotSupportedException(
            $"HMAC does not support hash {hash.Name}."),
    };
}
