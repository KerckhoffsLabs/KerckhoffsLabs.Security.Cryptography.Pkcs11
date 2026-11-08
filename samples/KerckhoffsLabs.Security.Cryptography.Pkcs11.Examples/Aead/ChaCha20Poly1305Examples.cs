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

    public static void GenerateChaCha20Key(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateChaCha20Key
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);
        //    Refuse a label already in use: a second key under it would make OpenKey ambiguous.
        if (session.TryOpenKey(keyLabel, out Pkcs11Key? existing))
        {
            existing.Dispose();
            throw new InvalidOperationException($"A key labelled '{keyLabel}' is already on the token.");
        }

        // 2. Generate a 256-bit ChaCha20 key (no helper generates one) on the token, from a template.
        //    ObjectTemplate.ForSecretKey starts sensitive (CKA_SENSITIVE: the value is never revealed) and
        //    non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token), with every role
        //    off; the template grants encryption and decryption only. OnToken() makes it a token object
        //    (CKA_TOKEN), which stays on the token when the session closes; without it the key is gone with
        //    the session. keyLabel becomes its CKA_LABEL, by which the application opens it: pick one no
        //    other key on the token has, as OpenKey refuses an ambiguous label.
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(keyLabel)
            .OnToken()
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_CHACHA20_KEY_GEN), template);
        // 3. The using declarations dispose the key handle, the session and the library. The key itself stays
        //    on the token.
        #endregion
    }

    public static byte[] ChaCha20Poly1305EncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext, byte[] associatedData)
    {
        #region ChaCha20Poly1305EncryptDecrypt
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the ChaCha20 key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it
        //    by CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var chacha = new ChaCha20Poly1305Pkcs11(key);

        // 3. Encrypt and decrypt on the token.
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[ciphertext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
        #endregion
        return decrypted;
    }
}
