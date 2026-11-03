using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/aead.md: AES-GCM, AES-CCM and ChaCha20-Poly1305.</summary>
public static class AeadExamples
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
