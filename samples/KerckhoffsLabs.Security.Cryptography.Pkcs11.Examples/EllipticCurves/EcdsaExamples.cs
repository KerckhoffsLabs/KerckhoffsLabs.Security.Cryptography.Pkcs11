using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ecdsa.md: ECDSA signatures with a token key.</summary>
public static class EcdsaExamples
{
    public static (byte[] Signature, ECParameters PublicKey) SignP256(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data)
    {
        #region SignP256
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the P-256 signing key pair that is already on the token, by its CKA_LABEL
        //    (OpenKey(id) finds it by CKA_ID instead): for example one
        //    GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256, label, persistOnToken: true) made.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var ecdsa = new ECDsaPkcs11(key);                 // an ECDsa: SignData, VerifyData, ...

        // 3. Sign on the token. IEEE P1363 (r || s), the BCL's default format; pass
        //    DSASignatureFormat.Rfc3279DerSequence for DER.
        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
        ECParameters publicKey = ecdsa.ExportParameters(includePrivateParameters: false);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
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
