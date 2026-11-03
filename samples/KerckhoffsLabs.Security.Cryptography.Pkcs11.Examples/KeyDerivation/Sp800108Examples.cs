using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/sp800-108.md: SP 800-108 counter-mode HMAC KDF, deriving into a token key.</summary>
public static class Sp800108Examples
{
    public static Pkcs11Key Sp800108DeriveAesKey(Pkcs11Key keyDerivationKey, byte[] label, byte[] context)
    {
        #region Sp800108DeriveAesKey
        // One master key on the token, many keys derived from it: the label names the purpose, the
        // context the party or tenant. Each derived key is created on the token.
        using var kdf = new SP800108HmacCounterKdfPkcs11(keyDerivationKey, HashAlgorithmName.SHA256);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        Pkcs11Key derived = kdf.DeriveKey(label, context, aesKey);
        #endregion
        return derived;
    }

    public static byte[] BclSp800108(byte[] keyDerivationKey, byte[] label, byte[] context)
    {
        #region BclSp800108
        byte[] derived = SP800108HmacCounterKdf.DeriveBytes(keyDerivationKey, HashAlgorithmName.SHA256, label, context, 32);
        #endregion
        return derived;
    }
}
