using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/slh-dsa.md: SLH-DSA (FIPS 205) signatures with a token key.</summary>
public static class SlhDsaExamples
{
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

    public static (byte[] Signature, byte[] PublicKey) BclSlhDsaSign(byte[] data)
    {
        #region BclSlhDsaSign
        // In software, where SlhDsa.IsSupported (OpenSSL 3.5 or later on Linux). The private key is in your process.
#pragma warning disable SYSLIB5006
        using SlhDsa slhDsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);

        byte[] signature = slhDsa.SignData(data);
        byte[] publicKey = slhDsa.ExportSlhDsaPublicKey();
#pragma warning restore SYSLIB5006
        #endregion
        return (signature, publicKey);
    }
}
