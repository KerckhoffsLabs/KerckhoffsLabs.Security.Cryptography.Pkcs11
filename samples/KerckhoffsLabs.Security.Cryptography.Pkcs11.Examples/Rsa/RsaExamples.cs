using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/rsa.md: RSA signatures and RSA-OAEP with a token key.</summary>
public static class RsaExamples
{
    public static (byte[] Signature, RSAParameters PublicKey) SignPss(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data)
    {
        #region SignPss
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the signing key pair that is already on the token, by its CKA_LABEL (OpenKey(id)
        //    finds it by CKA_ID instead): for example one GenerateRsaSigningKeyPair(3072, label,
        //    persistOnToken: true) made, allowed to sign and verify only. The private key is sensitive
        //    and non-extractable: only its public half can leave the token.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var rsa = new RSAPkcs11(key);                     // an RSA: SignData, VerifyData, ...

        // 3. Sign on the token, and export the public key for verifiers.
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
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

    [SuppressMessage("Security", "S5542:Use secure mode and padding scheme", Justification = "RSASSA-PKCS1-v1_5 *signatures* with SHA-256 are FIPS 186-5-approved and allowed by the default policy; the rule targets PKCS#1 v1.5 encryption, which docs/examples/rsa.md does not show.")]
    public static (byte[] Signature, RSAParameters PublicKey) BclSignPss(byte[] data)
    {
        #region BclSignPss
        using RSA rsa = RSA.Create(3072);                      // the private key is in your process

        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false);
        #endregion
        return (signature, publicKey);
    }

    public static (byte[] Signature, RSAParameters PublicKey) SignPkcs1v15(Pkcs11Key key, byte[] data)
    {
        #region SignPkcs1v15
        // RSASSA-PKCS1-v1_5 with SHA-256, for JWT RS256, X.509 and other formats that require it. The
        // signing key is opened as in the RSA-PSS example above; only the padding changes.
        using var rsa = new RSAPkcs11(key);
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        #endregion
        return (signature, rsa.ExportParameters(includePrivateParameters: false));
    }

    public static byte[] OaepEncryptDecrypt(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] plaintext)
    {
        #region OaepEncryptDecrypt
        // 1. Load the module and log in, as for signing.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the key-transport key pair that is already on the token, by its CKA_LABEL: encrypt
        //    and decrypt only, a different role from signing (GenerateRsaKeyTransportKeyPair makes one).
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var rsa = new RSAPkcs11(key);

        // 3. Encrypting uses the public key; anyone holding RSAParameters can do it with the BCL.
        byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        //    Decrypting runs on the token, with the private key that never leaves it.
        byte[] decrypted = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
        #endregion
        return decrypted;
    }

    [SuppressMessage("Security", "S5542:Use secure mode and padding scheme", Justification = "The software counterpart of SignPkcs1v15: RSASSA-PKCS1-v1_5 *signatures* with SHA-256 are FIPS 186-5-approved; the rule targets PKCS#1 v1.5 encryption.")]
    public static (byte[] Signature, RSAParameters PublicKey) BclSignPkcs1v15(byte[] data)
    {
        #region BclSignPkcs1v15
        using RSA rsa = RSA.Create(3072);
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        #endregion
        return (signature, rsa.ExportParameters(includePrivateParameters: false));
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
