using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

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

    public static byte[] AesCcmEncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext, byte[] associatedData)
    {
        #region AesCcmEncryptDecrypt
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the AES key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches. The key stays on the token.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var aesCcm = new AesCcmPkcs11(key, tagSizeInBytes: 16);   // the tag size is fixed here

        // 3. Encrypt and decrypt on the token.
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        aesCcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
        #endregion
        return decrypted;
    }
}
