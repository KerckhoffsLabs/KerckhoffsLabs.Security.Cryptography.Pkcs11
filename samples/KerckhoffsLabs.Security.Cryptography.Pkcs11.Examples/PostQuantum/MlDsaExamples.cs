using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ml-dsa.md: ML-DSA (FIPS 204) signatures with a token key.</summary>
public static class MlDsaExamples
{
    public static (byte[] Signature, byte[] PublicKey) MlDsaSign(string modulePath, string tokenLabel, SecurePin pin, byte[] data)
    {
        #region MlDsaSign
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. An ML-DSA-65 key pair on the token: the public key verifies, the private key signs. It is
        //    generated here, as session objects; a signing key you keep gets .Label(...) and .OnToken()
        //    on both templates, and is opened later with session.OpenKey(label).
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

        // 3. Sign on the token, and export the public key for verifiers.
        byte[] signature = mlDsa.SignData(data);
        byte[] publicKey = mlDsa.ExportMLDsaPublicKey();
        // 4. The using declarations dispose the adapter, the key, the session and the library, in
        //    reverse order.
        #endregion
        return (signature, publicKey);
    }

    public static (byte[] Signature, byte[] PublicKey) BclMlDsaSign(byte[] data)
    {
        #region BclMlDsaSign
        // In software, where MLDsa.IsSupported (OpenSSL 3.5 or later on Linux). The private key is in your process.
        using MLDsa mlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

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
}
