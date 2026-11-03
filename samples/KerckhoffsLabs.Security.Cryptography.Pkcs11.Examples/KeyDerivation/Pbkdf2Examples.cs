using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/pbkdf2.md: PBKDF2, deriving a token key from a password.</summary>
public static class Pbkdf2Examples
{
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
}
