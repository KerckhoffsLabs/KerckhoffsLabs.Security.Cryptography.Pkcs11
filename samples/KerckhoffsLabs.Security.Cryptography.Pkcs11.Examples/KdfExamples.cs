using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/key-derivation.md: HKDF, PBKDF2 and SP 800-108, keeping derived keys on the token.</summary>
public static class KdfExamples
{
    public static Pkcs11Key HkdfDeriveAesKey(Pkcs11Key inputKeyMaterial, byte[] salt, byte[] info)
    {
        #region HkdfDeriveAesKey
        // The derived key is created on the token from this template: AES-256, encrypt/decrypt only.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        // inputKeyMaterial is a token key with CKA_DERIVE: a shared secret, a master key, ...
        Pkcs11Key derived = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, aesKey, salt, info);
        #endregion
        return derived;
    }

    public static byte[] BclHkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info)
    {
        #region BclHkdf
        byte[] derived = HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength: 32, salt, info);
        #endregion
        return derived;
    }

    public static Pkcs11Key Pbkdf2DeriveAesKey(Pkcs11Session session, SecurePassword password, byte[] salt)
    {
        #region Pbkdf2DeriveAesKey
        // A key from a password: the password goes to the token in a SecurePassword (a pinned buffer
        // zeroed on dispose), and the AES key is created on the token. Use a random salt per password,
        // stored next to what the key protects, and at least 600 000 iterations of HMAC-SHA-256.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        Pkcs11Key derived = Rfc2898DeriveBytesPkcs11.Pbkdf2Key(
            session, password, salt, iterations: 600_000, HashAlgorithmName.SHA256, aesKey);
        #endregion
        return derived;
    }

    public static byte[] BclPbkdf2(byte[] password, byte[] salt)
    {
        #region BclPbkdf2
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations: 600_000, HashAlgorithmName.SHA256, outputLength: 32);
        #endregion
        return derived;
    }

    public static Pkcs11Key Sp800108DeriveAesKey(Pkcs11Key keyDerivationKey, byte[] label, byte[] context)
    {
        #region Sp800108DeriveAesKey
        // One master key on the token, many keys derived from it: the label names the purpose, the
        // context the party or tenant. Each derived key is created on the token.
        using var kdf = new SP800108HmacCounterKdfPkcs11(keyDerivationKey, HashAlgorithmName.SHA256);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        Pkcs11Key derived = kdf.DeriveKey(label, context, aesKey);
        #endregion
        return derived;
    }

    public static byte[] BclSp800108(byte[] keyDerivationKey, byte[] label, byte[] context)
    {
        #region BclSp800108
        byte[] derived = SP800108HmacCounterKdf.DeriveBytes(keyDerivationKey, HashAlgorithmName.SHA256, label, context, 32);
        #endregion
        return derived;
    }
}
