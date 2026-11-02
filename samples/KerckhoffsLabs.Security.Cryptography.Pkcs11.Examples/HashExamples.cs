using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/hashes.md: SHA-2, SHA-3 and HMAC on the token.</summary>
public static class HashExamples
{
    public static byte[] BclSha256(byte[] data)
    {
        #region BclSha256
        byte[] digest = SHA256.HashData(data);
        #endregion
        return digest;
    }

    public static byte[][] Sha2OnToken(Pkcs11Session session, byte[] data)
    {
        #region Sha2OnToken
        // Each adapter is a HashAlgorithm over the session: ComputeHash, TransformBlock, streams, ...
        using var sha256 = new SHA256Pkcs11(session);
        using var sha384 = new SHA384Pkcs11(session);
        using var sha512 = new SHA512Pkcs11(session);
        byte[][] digests = [sha256.ComputeHash(data), sha384.ComputeHash(data), sha512.ComputeHash(data)];
        #endregion
        return digests;
    }

    public static byte[][] Sha3OnToken(Pkcs11Session session, byte[] data)
    {
        #region Sha3OnToken
        using var sha3_256 = new SHA3_256Pkcs11(session);
        using var sha3_384 = new SHA3_384Pkcs11(session);
        using var sha3_512 = new SHA3_512Pkcs11(session);
        byte[][] digests = [sha3_256.ComputeHash(data), sha3_384.ComputeHash(data), sha3_512.ComputeHash(data)];
        #endregion
        return digests;
    }

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
