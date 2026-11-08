using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/sp800-108.md: SP 800-108 counter-mode HMAC KDF, deriving into a token key.</summary>
public static class Sp800108Examples
{
    public static void GenerateKeyDerivationKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateKeyDerivationKey
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

        // 2. Generate a 256-bit generic secret, the master key to derive from on the token, from a template.
        //    ObjectTemplate.ForSecretKey starts sensitive (CKA_SENSITIVE: the value is never revealed) and
        //    non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token), with every role
        //    off; the template grants derivation (CKA_DERIVE) only. OnToken() makes it a token object
        //    (CKA_TOKEN), which stays on the token when the session closes; without it the key is gone with
        //    the session. keyLabel becomes its CKA_LABEL, by which the application opens it: pick one no
        //    other key on the token has, as OpenKey refuses an ambiguous label.
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(keyLabel)
            .OnToken()
            .ValueLen(32)
            .Derive()
            .Build();
        using Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), template);
        // 3. The using declarations dispose the key handle, the session and the library. The key itself stays
        //    on the token.
        #endregion
    }

    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Sp800108DeriveAesKey(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] label, byte[] context, byte[] plaintext)
    {
        #region Sp800108DeriveAesKey
        // One master key on the token, many keys derived from it: the label names the purpose, the
        // context the party or tenant. Each derived key is created on the token.

        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the master key (a generic secret with CKA_DERIVE) already on the token, by its CKA_LABEL.
        using Pkcs11Key keyDerivationKey = session.OpenKey(keyLabel);

        // 3. Derive an AES-256 key for this purpose and tenant: a session object, gone when the session
        //    closes. The same label and context derive the same key again.
        using var kdf = new SP800108HmacCounterKdfPkcs11(keyDerivationKey, HashAlgorithmName.SHA256);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key derived = kdf.DeriveKey(label, context, aesKey);

        // 4. Use it: here, to encrypt with AES-GCM on the token.
        using var aesGcm = new AesGcmPkcs11(derived, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length], tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        // 5. The using declarations dispose the adapter, the keys, the KDF, the session and the library,
        //    in reverse order. The master key stays on the token.
        #endregion
        return (nonce, ciphertext, tag);
    }

    public static byte[] BclSp800108(byte[] keyDerivationKey, byte[] label, byte[] context)
    {
        #region BclSp800108
        byte[] derived = SP800108HmacCounterKdf.DeriveBytes(keyDerivationKey, HashAlgorithmName.SHA256, label, context, 32);
        #endregion
        return derived;
    }
}
