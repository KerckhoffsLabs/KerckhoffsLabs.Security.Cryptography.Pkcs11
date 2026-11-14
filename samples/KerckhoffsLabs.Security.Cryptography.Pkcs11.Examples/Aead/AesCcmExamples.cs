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

    public static void GenerateAesCcmKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateAesCcmKey
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();
        //    Refuse a label already in use: a second key under it would make OpenKey ambiguous.
        if (session.TryOpenKey(keyLabel, out Pkcs11Key? existing))
        {
            existing.Dispose();
            throw new InvalidOperationException($"A key labelled '{keyLabel}' is already on the token.");
        }

        // 2. Generate an AES-256 key on the token. The helper makes it sensitive (CKA_SENSITIVE: its value is
        //    never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token),
        //    and allows encryption and decryption only. persistOnToken: true makes it a token object
        //    (CKA_TOKEN), which stays on the token when the session closes; without it the key is gone with
        //    the session. keyLabel becomes its CKA_LABEL, by which the application opens it: pick one no
        //    other key on the token has, as OpenKey refuses an ambiguous label.
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256, label: keyLabel, persistOnToken: true);
        // 3. The using declarations dispose the key handle, the session and the library. The key itself stays
        //    on the token.
        #endregion
    }

    public static byte[] AesCcmEncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext, byte[] associatedData)
    {
        #region AesCcmEncryptDecrypt
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();

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
