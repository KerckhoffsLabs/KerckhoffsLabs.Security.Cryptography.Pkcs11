using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ecdsa.md: ECDSA signatures with a token key.</summary>
public static class EcdsaExamples
{
    public static (byte[] Signature, ECParameters PublicKey) SignP256(Pkcs11Session session, byte[] data)
    {
        #region SignP256
        using Pkcs11Key key = session.GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256, label: "api-signing");
        using var ecdsa = new ECDsaPkcs11(key);                 // an ECDsa: SignData, VerifyData, ...

        // IEEE P1363 (r || s), the BCL's default format; pass DSASignatureFormat.Rfc3279DerSequence for DER.
        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
        ECParameters publicKey = ecdsa.ExportParameters(includePrivateParameters: false);
        #endregion
        return (signature, publicKey);
    }

    public static (byte[] Signature, ECParameters PublicKey) BclSignP256(byte[] data)
    {
        #region BclSignP256
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);   // the private key is in your process

        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
        ECParameters publicKey = ecdsa.ExportParameters(includePrivateParameters: false);
        #endregion
        return (signature, publicKey);
    }

    public static bool VerifyWithBcl(byte[] data, byte[] signature, ECParameters publicKey)
    {
        #region VerifyWithBcl
        using ECDsa verifier = ECDsa.Create(publicKey);         // plain BCL, no token
        return verifier.VerifyData(data, signature, HashAlgorithmName.SHA256);
        #endregion
    }
}
