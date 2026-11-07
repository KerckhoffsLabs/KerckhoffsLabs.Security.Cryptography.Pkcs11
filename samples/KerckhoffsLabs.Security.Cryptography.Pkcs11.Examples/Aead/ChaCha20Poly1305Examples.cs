using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/chacha20-poly1305.md: ChaCha20-Poly1305 with a token key.</summary>
public static class ChaCha20Poly1305Examples
{
    public static byte[] BclChaCha20Poly1305EncryptDecrypt(byte[] plaintext, byte[] associatedData)
    {
        #region BclChaCha20Poly1305EncryptDecrypt
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var chacha = new ChaCha20Poly1305(key);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }

    public static byte[] ChaCha20Poly1305EncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, byte[] plaintext, byte[] associatedData)
    {
        #region ChaCha20Poly1305EncryptDecrypt
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Generate a key on the token. No helper generates a ChaCha20 key, so build the template:
        //    256 bits, encrypt and decrypt only. The builder makes it sensitive and non-extractable, and
        //    leaves every other role off. It is a session object, gone when the session closes; add
        //    .Label("...") and .OnToken() to keep it, and open it later with session.OpenKey("...").
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_CHACHA20_KEY_GEN), template);
        using var chacha = new ChaCha20Poly1305Pkcs11(key);

        // 3. Encrypt and decrypt on the token.
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        // 4. The using declarations dispose the adapter, the key, the session and the library, in
        //    reverse order.
        #endregion
        return decrypted;
    }
}
