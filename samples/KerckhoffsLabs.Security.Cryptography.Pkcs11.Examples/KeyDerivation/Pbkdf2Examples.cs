using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/pbkdf2.md: PBKDF2, deriving a token key from a password.</summary>
public static class Pbkdf2Examples
{
    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Pbkdf2DeriveAesKey(
        string modulePath, string tokenLabel, SecurePin pin, SecurePassword password, byte[] salt, byte[] plaintext)
    {
        #region Pbkdf2DeriveAesKey
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        //    The PIN unlocks the token; the password below is the one the key is derived from.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. A key from a password: the password goes to the token in a SecurePassword (a pinned buffer
        //    zeroed on dispose), and the AES key is created on the token. Use a random salt per password,
        //    stored next to what the key protects, and at least 600 000 iterations of HMAC-SHA-256.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key derived = Rfc2898DeriveBytesPkcs11.Pbkdf2Key(
            session, password, salt, iterations: 600_000, HashAlgorithmName.SHA256, aesKey);

        // 3. Use it: here, to encrypt with AES-GCM on the token.
        using var aesGcm = new AesGcmPkcs11(derived, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length], tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        // 4. The using declarations dispose the adapter, the key (a session object: gone with the
        //    session), the session and the library, in reverse order.
        #endregion
        return (nonce, ciphertext, tag);
    }

    public static byte[] BclPbkdf2(byte[] password, byte[] salt)
    {
        #region BclPbkdf2
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations: 600_000, HashAlgorithmName.SHA256, outputLength: 32);
        #endregion
        return derived;
    }
}
