using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/hkdf.md: HKDF, deriving into a token key.</summary>
public static class HkdfExamples
{
    public static Pkcs11Key HkdfDeriveAesKey(Pkcs11Key inputKeyMaterial, byte[] salt, byte[] info)
    {
        #region HkdfDeriveAesKey
        // The derived key is created on the token from this template: AES-256, encrypt/decrypt only.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        // inputKeyMaterial is a token key with CKA_DERIVE: a shared secret, a master key, ...
        Pkcs11Key derived = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, aesKey, salt, info);
        #endregion
        return derived;
    }

    public static byte[] BclHkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info)
    {
        #region BclHkdf
        byte[] derived = HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength: 32, salt, info);
        #endregion
        return derived;
    }
}
