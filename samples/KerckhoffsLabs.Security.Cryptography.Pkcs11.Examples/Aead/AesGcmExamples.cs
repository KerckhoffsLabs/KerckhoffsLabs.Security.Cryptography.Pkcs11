using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

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

    public static byte[] AesGcmEncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext, byte[] associatedData)
    {
        #region AesGcmEncryptDecrypt
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the AES key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches. The key stays on the token.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var aesGcm = new AesGcmPkcs11(key, tagSizeInBytes: 16);

        // 3. Encrypt and decrypt on the token.
        byte[] nonce = session.GenerateRandom(12);                      // never reuse a nonce with a key
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
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
