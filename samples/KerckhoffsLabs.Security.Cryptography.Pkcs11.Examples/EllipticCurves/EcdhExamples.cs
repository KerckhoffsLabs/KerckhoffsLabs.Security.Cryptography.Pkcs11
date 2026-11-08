using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ecdh.md: ECDH key agreement, keeping the shared secret and the derived key on the token.</summary>
public static class EcdhExamples
{
    public static byte[] GenerateEcdhKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateEcdhKey
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

        // 2. Generate a P-256 key-agreement key pair on the token. The private key is sensitive
        //    (CKA_SENSITIVE: never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped
        //    off the token); the private key may derive (agree on keys) only. persistOnToken: true makes both
        //    halves token objects (CKA_TOKEN), which stay on the token when the session closes; without it
        //    the pair is gone with the session. keyLabel becomes the CKA_LABEL of both halves, by which the
        //    application opens it: pick one no other key on the token has, as OpenKey refuses an ambiguous
        //    label.
        using Pkcs11Key key = session.GenerateEcKeyAgreementKeyPair(
            Pkcs11ECCurve.NamedCurves.NistP256, label: keyLabel, persistOnToken: true);

        // 3. Export the public half (SubjectPublicKeyInfo DER), to send to the other party.
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        byte[] publicKey = ecdh.ExportSubjectPublicKeyInfo();
        // 4. The using declarations dispose the adapter, the key handle, the session and the library. The key
        //    pair stays on the token.
        #endregion
        return publicKey;
    }

    public static byte[] AgreeAesKeyWithBclPeer(string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] message)
    {
        #region AgreeAesKeyWithBclPeer
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Our side: open our key-agreement key pair, already on the token, by its CKA_LABEL. Both
        //    halves carry the label, so OpenKey returns the pair. The other party: any ECDH
        //    implementation, here the BCL's. The two exchange public keys.
        using Pkcs11Key ours = session.OpenKey(keyLabel);
        using var ourEcdh = new ECDiffieHellmanPkcs11(ours);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] peerPublicKey = peer.PublicKey.ExportSubjectPublicKeyInfo();
        //    They also agree on HKDF's inputs: a random salt, sent along with the public keys, and an info
        //    string that binds the key to its purpose.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] info = "example.com/v1 session key"u8.ToArray();

        // 3. On the token: the shared secret Z stays a token object (it can only feed a KDF), and HKDF
        //    turns it into an AES-256 key that never leaves the token either. Both are session objects,
        //    gone with the session.
        using Pkcs11Key sharedSecret = ours.DeriveSecretAgreement(peerPublicKey);
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key tokenKey = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, salt, info);

        // 4. The token encrypts a message with its key.
        using var aesGcm = new AesGcmPkcs11(tokenKey, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[message.Length], tag = new byte[16];
        aesGcm.Encrypt(nonce, message, ciphertext, tag);

        // 5. The peer computes the same Z and runs the same HKDF, in software, so it holds the same key and
        //    decrypts. Z and the peer's key are bytes in its process: zero them, also when a step fails.
        byte[] z = peer.DeriveRawSecretAgreement(ourEcdh.PublicKey);
        byte[] peerKey;
        try
        {
            peerKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, outputLength: 32, salt, info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }

        byte[] received = new byte[ciphertext.Length];
        try
        {
            using var peerAesGcm = new AesGcm(peerKey, tagSizeInBytes: 16);
            peerAesGcm.Decrypt(nonce, ciphertext, tag, received);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerKey);
        }
        // 6. The using declarations dispose the adapters, the derived keys, the key-pair handle (the pair
        //    stays on the token), the session and the library, in reverse order.
        #endregion
        return received;
    }

    public static (byte[] OurKey, byte[] PeerKey) BclAgreeAesKey()
    {
        #region BclAgreeAesKey
        // Both sides in software. The two exchange public keys, and agree on HKDF's inputs: a random salt,
        // sent along with the public keys, and an info string that binds the key to its purpose.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] info = "example.com/v1 session key"u8.ToArray();
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
