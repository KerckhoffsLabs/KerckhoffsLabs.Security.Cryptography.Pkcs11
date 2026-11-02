using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/post-quantum.md: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).</summary>
public static class PqcExamples
{
    public static (Pkcs11Key TokenKey, byte[] SenderKey) MlKemReceiveAesKey(Pkcs11Session session)
    {
        #region MlKemReceiveAesKey
        // The receiver: an ML-KEM-768 key pair on the token. The public half (the encapsulation key)
        // may encapsulate; the private half (the decapsulation key) may decapsulate. No helper
        // generates ML-KEM keys, so the templates name the parameter set and the two roles.
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_DECAPSULATE, true)
            .Build();
        using Pkcs11Key receiver = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var mlKem = new MLKemPkcs11(receiver);            // an MLKem
        byte[] encapsulationKey = mlKem.ExportEncapsulationKey(); // published to senders

        // The sender: any ML-KEM implementation, here the BCL's. It gets a 32-byte shared secret and a
        // ciphertext, which it sends to the receiver.
        using MLKem sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey);
        sender.Encapsulate(out byte[] ciphertext, out byte[] senderSecret);

        // The receiver decapsulates on the token, straight into an AES-256 key: the shared secret
        // never leaves the token.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Encrypt()
            .Decrypt()
            .Build();
        Pkcs11Key tokenKey = receiver.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), ciphertext, aesKey);
        #endregion
        return (tokenKey, senderSecret);
    }

    public static (byte[] Signature, byte[] PublicKey) MlDsaSign(Pkcs11Session session, byte[] data)
    {
        #region MlDsaSign
        // An ML-DSA-65 key pair on the token: the public key verifies, the private key signs.
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65)
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var mlDsa = new MLDsaPkcs11(key);                 // an MLDsa: SignData, VerifyData, ...

        byte[] signature = mlDsa.SignData(data);
        byte[] publicKey = mlDsa.ExportMLDsaPublicKey();
        #endregion
        return (signature, publicKey);
    }

    public static bool MlDsaVerifyWithBcl(byte[] data, byte[] signature, byte[] publicKey)
    {
        #region MlDsaVerifyWithBcl
        using MLDsa verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
        return verifier.VerifyData(data, signature);
        #endregion
    }

    public static (byte[] Signature, byte[] PublicKey) SlhDsaSign(Pkcs11Session session, byte[] data)
    {
        #region SlhDsaSign
        // SlhDsa and its adapter are [Experimental] in .NET 10 (SYSLIB5006): the API may still change.
#pragma warning disable SYSLIB5006
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var slhDsa = new SlhDsaPkcs11(key);               // an SlhDsa

        byte[] signature = slhDsa.SignData(data);               // small "s" sets: slow to sign, small signatures
        byte[] publicKey = slhDsa.ExportSlhDsaPublicKey();
#pragma warning restore SYSLIB5006
        #endregion
        return (signature, publicKey);
    }
}
