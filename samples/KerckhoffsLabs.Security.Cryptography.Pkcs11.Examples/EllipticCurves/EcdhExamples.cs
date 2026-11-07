using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ecdh.md: ECDH key agreement, keeping the shared secret and the derived key on the token.</summary>
public static class EcdhExamples
{
    public static byte[] AgreeAesKeyWithBclPeer(string modulePath, string tokenLabel, SecurePin pin, byte[] message)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(32);      // sent along with the public keys
        byte[] info = "example.com/v1 session key"u8.ToArray(); // binds the key to its purpose

        #region AgreeAesKeyWithBclPeer
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Our side: a P-256 key pair on the token, generated for this exchange (a long-term one is
        //    opened instead with session.OpenKey(label)). The other party: any ECDH implementation, here
        //    the BCL's. The two exchange public keys.
        using Pkcs11Key ours = session.GenerateEcKeyAgreementKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ourEcdh = new ECDiffieHellmanPkcs11(ours);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] peerPublicKey = peer.PublicKey.ExportSubjectPublicKeyInfo();

        // 3. On the token: the shared secret Z stays a token object (it can only feed a KDF), and HKDF
        //    turns it into an AES-256 key that never leaves the token either.
        using Pkcs11Key sharedSecret = ours.DeriveSecretAgreement(peerPublicKey);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key tokenKey = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, salt, info);

        // 4. The peer computes the same Z and runs the same HKDF, in software.
        byte[] z = peer.DeriveRawSecretAgreement(ourEcdh.PublicKey);
        byte[] peerKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, outputLength: 32, salt, info);
        CryptographicOperations.ZeroMemory(z);

        // 5. Both hold the same key: what the token encrypts with it, the peer decrypts.
        using var aesGcm = new AesGcmPkcs11(tokenKey, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[message.Length], tag = new byte[16];
        aesGcm.Encrypt(nonce, message, ciphertext, tag);

        using var peerAesGcm = new AesGcm(peerKey, tagSizeInBytes: 16);
        byte[] received = new byte[ciphertext.Length];
        peerAesGcm.Decrypt(nonce, ciphertext, tag, received);
        // 6. The using declarations dispose the adapters, the keys (session objects: gone with the
        //    session), the session and the library, in reverse order.
        #endregion
        return received;
    }

    public static (byte[] OurKey, byte[] PeerKey) BclAgreeAesKey()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(32);      // sent along with the public keys
        byte[] info = "example.com/v1 session key"u8.ToArray(); // binds the key to its purpose

        #region BclAgreeAesKey
        // Both sides in software. The two exchange public keys.
        using ECDiffieHellman ours = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // The shared secret Z and the AES key are bytes in your process: zero Z once HKDF has used it.
        byte[] z = ours.DeriveRawSecretAgreement(peer.PublicKey);
        byte[] ourKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, outputLength: 32, salt, info);
        CryptographicOperations.ZeroMemory(z);

        // The peer computes the same Z and runs the same HKDF.
        byte[] peerZ = peer.DeriveRawSecretAgreement(ours.PublicKey);
        byte[] peerKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, peerZ, outputLength: 32, salt, info);
        CryptographicOperations.ZeroMemory(peerZ);
        #endregion
        return (ourKey, peerKey);
    }
}
