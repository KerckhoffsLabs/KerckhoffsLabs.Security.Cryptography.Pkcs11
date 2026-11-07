using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/aes.md: AES in an unauthenticated block mode, for interop only.</summary>
public static class AesModeExamples
{
    public static byte[] BclCbcPad(byte[] plaintext)
    {
        #region BclCbcPad
        using Aes aes = Aes.Create();
        aes.Key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);

        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        byte[] decrypted = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        #endregion
        return decrypted;
    }

    public static void GenerateArchiveKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateArchiveKey
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Generate an AES-256 key on the token. The helper makes it sensitive (CKA_SENSITIVE: its value is
        //    never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token),
        //    and allows encryption and decryption only. persistOnToken: true makes it a token object
        //    (CKA_TOKEN), which stays on the token when the session closes; without it the key is gone with
        //    the session. keyLabel becomes its CKA_LABEL, by which the application opens it: pick one no
        //    other key on the token has, as OpenKey refuses an ambiguous label. Generating an AES key needs
        //    no policy of its own: the reviewed policy governs the CBC operations.
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256, label: keyLabel, persistOnToken: true);
        // 3. The using declarations dispose the key handle, the session and the library. The key itself stays
        //    on the token.
        #endregion
    }

    public static byte[] CbcPadUnderReviewedPolicy(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext)
    {
        #region CbcPadUnderReviewedPolicy
        // 1. Recommended refuses every unauthenticated AES mode. A file format that requires AES-CBC
        //    gets a policy of its own, derived from Recommended: it allows that one mechanism, for the
        //    operations named, with the reason recorded; every other Recommended rule still applies.
        ComposedCryptoPolicy legacyFormat = CryptoPolicy.Recommended.ToBuilder("LegacyArchiveFormat")
            .AllowMechanism(
                CKM.CKM_AES_CBC_PAD,
                [CryptoOperation.Encrypt, CryptoOperation.Decrypt],
                "The archive format we exchange with the partner is AES-256-CBC with PKCS#7 padding; " +
                "each archive is signed separately, which supplies the integrity CBC lacks.")
            .Build();

        // 2. Load the module and log in, under that policy. The module path and token label come from
        //    configuration; the PIN from your secret store (see ReadPinFromEnvironment in Getting
        //    started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin, legacyFormat);

        // 3. Open the AES key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var aes = new AesPkcs11(key);                    // an Aes: EncryptCbc, DecryptCbc, ...
        byte[] iv = session.GenerateRandom(16);                // a fresh, unpredictable IV per message

        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);     // CKM_AES_CBC_PAD
        byte[] decrypted = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
        #endregion
        return decrypted;
    }
}
