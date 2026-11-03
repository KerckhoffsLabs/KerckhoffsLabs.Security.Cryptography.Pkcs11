using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/hmac.md: HMAC with a token key.</summary>
public static class HmacExamples
{
    public static Pkcs11Key GenerateHmacKey(Pkcs11Session session)
    {
        #region GenerateHmacKey
        // A 256-bit generic secret on the token, allowed to sign (compute) and verify HMACs only.
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(32)
            .Sign()
            .Verify()
            .Build();
        Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), template);
        #endregion
        return key;
    }

    public static byte[] HmacSha256(Pkcs11Key key, byte[] data)
    {
        #region HmacSha256
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);   // an HMAC
        byte[] tag = hmac.ComputeHash(data);
        #endregion
        return tag;
    }

    public static byte[] BclHmacSha256(byte[] key, byte[] data)
    {
        #region BclHmacSha256
        using var hmac = new HMACSHA256(key);                  // the key is bytes in your process
        byte[] tag = hmac.ComputeHash(data);
        #endregion
        return tag;
    }
}
