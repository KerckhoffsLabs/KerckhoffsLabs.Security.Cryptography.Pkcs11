using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ml-dsa.md: ML-DSA (FIPS 204) signatures with a token key.</summary>
public static class MlDsaExamples
{
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
}
