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

    public static byte[] ChaCha20Poly1305EncryptDecrypt(Pkcs11Session session, byte[] plaintext, byte[] associatedData)
    {
        #region ChaCha20Poly1305EncryptDecrypt
        // No helper generates a ChaCha20 key, so build the template: 256 bits, encrypt and decrypt
        // only. The builder makes it sensitive and non-extractable, and leaves every other role off.
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_CHACHA20_KEY_GEN), template);
        using var chacha = new ChaCha20Poly1305Pkcs11(key);

        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }
}
