using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/elliptic-curves.md: ECDSA signatures and ECDH key agreement.</summary>
public static class EcExamples
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

    public static bool VerifyWithBcl(byte[] data, byte[] signature, ECParameters publicKey)
    {
        #region VerifyWithBcl
        using ECDsa verifier = ECDsa.Create(publicKey);         // plain BCL, no token
        return verifier.VerifyData(data, signature, HashAlgorithmName.SHA256);
        #endregion
    }

    public static (Pkcs11Key TokenKey, byte[] PeerKey) AgreeAesKeyWithBclPeer(Pkcs11Session session)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(32);      // sent along with the public keys
        byte[] info = "example.com/v1 session key"u8.ToArray(); // binds the key to its purpose

        #region AgreeAesKeyWithBclPeer
        // Our side: a P-256 key pair on the token. The other party: any ECDH implementation, here
        // the BCL's. The two exchange public keys.
        using Pkcs11Key ours = session.GenerateEcKeyAgreementKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ourEcdh = new ECDiffieHellmanPkcs11(ours);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] peerPublicKey = peer.PublicKey.ExportSubjectPublicKeyInfo();

        // On the token: the shared secret Z stays a token object (it can only feed a KDF), and HKDF
        // turns it into an AES-256 key that never leaves the token either.
        using Pkcs11Key sharedSecret = ours.DeriveSecretAgreement(peerPublicKey);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        Pkcs11Key tokenKey = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, salt, info);

        // The peer computes the same Z and runs the same HKDF, in software.
        byte[] z = peer.DeriveRawSecretAgreement(ourEcdh.PublicKey);
        byte[] peerKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, outputLength: 32, salt, info);
        CryptographicOperations.ZeroMemory(z);
        #endregion
        return (tokenKey, peerKey);
    }
}
