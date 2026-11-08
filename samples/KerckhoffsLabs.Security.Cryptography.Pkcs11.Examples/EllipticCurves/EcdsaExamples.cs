using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ecdsa.md: ECDSA signatures with a token key.</summary>
public static class EcdsaExamples
{
    public static byte[] GenerateEcdsaKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateEcdsaKey
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);
        //    Refuse a label already in use: a second key under it would make OpenKey ambiguous.
        if (session.TryOpenKey(keyLabel, out Pkcs11Key? existing))
        {
            existing.Dispose();
            throw new InvalidOperationException($"A key labelled '{keyLabel}' is already on the token.");
        }

        // 2. Generate a P-256 signing key pair on the token. The private key is sensitive (CKA_SENSITIVE:
        //    never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token);
        //    the pair may sign and verify only. persistOnToken: true makes both halves token objects
        //    (CKA_TOKEN), which stay on the token when the session closes; without it the pair is gone with
        //    the session. keyLabel becomes the CKA_LABEL of both halves, by which the application opens it:
        //    pick one no other key on the token has, as OpenKey refuses an ambiguous label.
        using Pkcs11Key key = session.GenerateEcSigningKeyPair(
            Pkcs11ECCurve.NamedCurves.NistP256, label: keyLabel, persistOnToken: true);

        // 3. Export the public half (SubjectPublicKeyInfo DER), for those who verify the signatures.
        using var ecdsa = new ECDsaPkcs11(key);
        byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        // 4. The using declarations dispose the adapter, the key handle, the session and the library. The key
        //    pair stays on the token.
        #endregion
        return publicKey;
    }

    public static (byte[] Signature, ECParameters PublicKey) SignP256(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data)
    {
        #region SignP256
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the P-256 signing key pair that is already on the token (generated as above), by its
        //    CKA_LABEL; OpenKey(id) finds it by CKA_ID instead. Both halves carry the label, so OpenKey
        //    returns the pair.
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
