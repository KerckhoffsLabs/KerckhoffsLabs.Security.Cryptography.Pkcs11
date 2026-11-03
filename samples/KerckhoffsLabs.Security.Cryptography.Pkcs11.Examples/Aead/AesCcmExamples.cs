using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/aes-ccm.md: AES-CCM with a token key.</summary>
public static class AesCcmExamples
{
    public static byte[] BclAesCcmEncryptDecrypt(byte[] plaintext, byte[] associatedData)
    {
        #region BclAesCcmEncryptDecrypt
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var aesCcm = new AesCcm(key);                        // the tag size comes from each call's tag

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesCcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }

    public static byte[] AesCcmEncryptDecrypt(Pkcs11Session session, byte[] plaintext, byte[] associatedData)
    {
        #region AesCcmEncryptDecrypt
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256);
        using var aesCcm = new AesCcmPkcs11(key, tagSizeInBytes: 16);   // the tag size is fixed here

        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesCcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }
}
