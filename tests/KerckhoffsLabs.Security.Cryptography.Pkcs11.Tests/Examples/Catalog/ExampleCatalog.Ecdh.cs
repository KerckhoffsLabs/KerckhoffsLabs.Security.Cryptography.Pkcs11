using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/ecdh.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] EcdhCases() =>
    [
        new(Name(nameof(EcdhExamples), nameof(EcdhExamples.AgreeAesKeyWithBclPeer)), [typeof(ECDiffieHellmanPkcs11)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE, CKM.CKM_HKDF_DERIVE, CKM.CKM_AES_GCM],
            ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (Pkcs11Key tokenKey, byte[] peerKey) = EcdhExamples.AgreeAesKeyWithBclPeer(s);
                using (tokenKey)
                {
                    // The two keys are the same: what the token encrypts, the peer decrypts.
                    using var onToken = new AesGcmPkcs11(tokenKey, 16);
                    byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
                    onToken.Encrypt(nonce, Message, ciphertext, tag);
                    using var atPeer = new AesGcm(peerKey, 16);
                    byte[] decrypted = new byte[ciphertext.Length];
                    atPeer.Decrypt(nonce, ciphertext, tag, decrypted);
                    Assert.Equal(Message, decrypted);
                }

                // The BCL-shaped DeriveKey* methods return the shared secret into the process, which
                // the default policy refuses.
                using Pkcs11Key ec = s.GenerateEcKeyAgreementKeyPair();
                using var ecdh = new ECDiffieHellmanPkcs11(ec);
                using ECDiffieHellman other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                Assert.Throws<CryptoPolicyViolationException>(() => ecdh.DeriveKeyFromHash(other.PublicKey, HashAlgorithmName.SHA256));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),
    ];
}
