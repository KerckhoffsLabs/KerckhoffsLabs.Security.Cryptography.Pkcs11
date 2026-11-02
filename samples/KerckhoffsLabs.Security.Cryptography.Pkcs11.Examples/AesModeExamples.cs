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

    public static byte[] CbcPadUnderReviewedPolicy(Pkcs11Library library, string tokenLabel, SecurePin pin, byte[] plaintext)
    {
        #region CbcPadUnderReviewedPolicy
        // Recommended refuses every unauthenticated AES mode. A file format that requires AES-CBC
        // gets a policy of its own, derived from Recommended: it allows that one mechanism, for the
        // operations named, with the reason recorded; every other Recommended rule still applies.
        ComposedCryptoPolicy legacyFormat = CryptoPolicy.Recommended.ToBuilder("LegacyArchiveFormat")
            .AllowMechanism(
                CKM.CKM_AES_CBC_PAD,
                [CryptoOperation.Encrypt, CryptoOperation.Decrypt],
                "The archive format we exchange with the partner is AES-256-CBC with PKCS#7 padding; " +
                "each archive is signed separately, which supplies the integrity CBC lacks.")
            .Build();
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin, legacyFormat);

        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256);
        using var aes = new AesPkcs11(key);                    // an Aes: EncryptCbc, DecryptCbc, ...
        byte[] iv = session.GenerateRandom(16);                // a fresh, unpredictable IV per message

        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);     // CKM_AES_CBC_PAD
        byte[] decrypted = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        #endregion
        return decrypted;
    }
}
