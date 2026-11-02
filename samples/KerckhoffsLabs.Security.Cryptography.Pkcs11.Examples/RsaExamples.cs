using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/rsa.md: RSA signatures and RSA-OAEP with a token key.</summary>
public static class RsaExamples
{
    public static (byte[] Signature, RSAParameters PublicKey) SignPss(Pkcs11Session session, byte[] data)
    {
        #region SignPss
        // A 3072-bit key pair on the token, allowed to sign and verify only. The private key is
        // sensitive and non-extractable: only its public half can leave the token.
        using Pkcs11Key key = session.GenerateRsaSigningKeyPair(modulusBits: 3072, label: "release-signing");
        using var rsa = new RSAPkcs11(key);                     // an RSA: SignData, VerifyData, ...

        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false);
        #endregion
        return (signature, publicKey);
    }

    public static bool VerifyPssWithBcl(byte[] data, byte[] signature, RSAParameters publicKey)
    {
        #region VerifyPssWithBcl
        // Anyone with the public key verifies with the plain BCL: no token, no PKCS#11.
        using RSA verifier = RSA.Create(publicKey);
        return verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        #endregion
    }

    public static (byte[] Signature, RSAParameters PublicKey) SignPkcs1v15(Pkcs11Session session, byte[] data)
    {
        #region SignPkcs1v15
        // RSASSA-PKCS1-v1_5 with SHA-256, for JWT RS256, X.509 and other formats that require it.
        using Pkcs11Key key = session.GenerateRsaSigningKeyPair(modulusBits: 3072);
        using var rsa = new RSAPkcs11(key);
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        #endregion
        return (signature, rsa.ExportParameters(includePrivateParameters: false));
    }

    public static byte[] OaepEncryptDecrypt(Pkcs11Session session, byte[] plaintext)
    {
        #region OaepEncryptDecrypt
        // A key-transport key pair: encrypt and decrypt only, a different role from signing.
        using Pkcs11Key key = session.GenerateRsaKeyTransportKeyPair(modulusBits: 3072);
        using var rsa = new RSAPkcs11(key);

        // Encrypting uses the public key; anyone holding RSAParameters can do it with the BCL.
        byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        // Decrypting runs on the token, with the private key that never leaves it.
        byte[] decrypted = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        #endregion
        return decrypted;
    }

    public static byte[] BclOaepEncryptDecrypt(byte[] plaintext)
    {
        #region BclOaepEncryptDecrypt
        using RSA rsa = RSA.Create(3072);                      // the private key is in your process
        byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        byte[] decrypted = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        #endregion
        return decrypted;
    }
}
