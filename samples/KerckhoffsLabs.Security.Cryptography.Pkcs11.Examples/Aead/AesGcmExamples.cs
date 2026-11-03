using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/aes-gcm.md: AES-GCM with a token key.</summary>
public static class AesGcmExamples
{
    public static byte[] BclAesGcmEncryptDecrypt(byte[] plaintext, byte[] associatedData)
    {
        #region BclAesGcmEncryptDecrypt
        byte[] key = RandomNumberGenerator.GetBytes(32);           // the key is bytes in your process
        using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);         // never reuse a nonce with a key
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }

    public static byte[] AesGcmEncryptDecrypt(Pkcs11Session session, byte[] plaintext, byte[] associatedData)
    {
        #region AesGcmEncryptDecrypt
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256);   // the key stays on the token
        using var aesGcm = new AesGcmPkcs11(key, tagSizeInBytes: 16);

        byte[] nonce = session.GenerateRandom(12);                      // never reuse a nonce with a key
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        #endregion
        return decrypted;
    }

    public static bool AesGcmDetectsTampering(Pkcs11Session session, byte[] plaintext)
    {
        using Pkcs11Key key = session.GenerateAesKey();
        using var aesGcm = new AesGcmPkcs11(key, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        #region AesGcmDetectsTampering
        ciphertext[0] ^= 1;                                   // one flipped bit in transit
        byte[] decrypted = new byte[ciphertext.Length];
        try
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, decrypted);
            return false;
        }
        catch (CryptographicException)
        {
            // Usually AuthenticationTagMismatchException, as from the BCL's AesGcm; a token that reports
            // a bad tag with a generic code surfaces as a Pkcs11Exception instead. Both derive from
            // CryptographicException: reject the message either way, and never use `decrypted`.
            return true;
        }
        #endregion
    }
}
