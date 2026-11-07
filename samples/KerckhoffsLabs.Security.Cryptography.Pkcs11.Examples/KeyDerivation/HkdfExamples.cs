using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/hkdf.md: HKDF, deriving into a token key.</summary>
public static class HkdfExamples
{
    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) HkdfDeriveAesKey(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] salt, byte[] info, byte[] plaintext)
    {
        #region HkdfDeriveAesKey
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the input key material already on the token, by its CKA_LABEL: a key with CKA_DERIVE
        //    (a shared secret, a master key, ...).
        using Pkcs11Key inputKeyMaterial = session.OpenKey(keyLabel);

        // 3. Derive on the token. The derived key is created from this template: AES-256,
        //    encrypt/decrypt only. It is a session object, gone when the session closes.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key derived = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, aesKey, salt, info);

        // 4. Use it: here, to encrypt with AES-GCM on the token.
        using var aesGcm = new AesGcmPkcs11(derived, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length], tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        // 5. The using declarations dispose the adapter, the keys, the session and the library, in
        //    reverse order. The input key material stays on the token.
        #endregion
        return (nonce, ciphertext, tag);
    }

    public static byte[] BclHkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info)
    {
        #region BclHkdf
        byte[] derived = HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength: 32, salt, info);
        #endregion
        return derived;
    }
}
