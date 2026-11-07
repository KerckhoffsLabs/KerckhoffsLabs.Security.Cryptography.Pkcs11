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
            b =>
            {
                // The example agrees on a key with the peer, encrypts on the token, and the peer decrypts:
                // the message comes back only if both sides hold the same key.
                using (SecurePin pin = UserPin(b))
                    Assert.Equal(Message, EcdhExamples.AgreeAesKeyWithBclPeer(b.LibraryPath, b.TokenLabel, pin, Message));
                AssertFixtureLibraryStillWorks(b);

                // The BCL-shaped DeriveKey* methods return the shared secret into the process, which
                // the default policy refuses.
                using Pkcs11Session s = b.OpenSession();
                using Pkcs11Key ec = s.GenerateEcKeyAgreementKeyPair();
                using var ecdh = new ECDiffieHellmanPkcs11(ec);
                using ECDiffieHellman other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                Assert.Throws<CryptoPolicyViolationException>(() => ecdh.DeriveKeyFromHash(other.PublicKey, HashAlgorithmName.SHA256));
            },
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(EcdhExamples), nameof(EcdhExamples.BclAgreeAesKey)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                (byte[] ourKey, byte[] peerKey) = EcdhExamples.BclAgreeAesKey();
                Assert.Equal(32, ourKey.Length);
                Assert.Equal(ourKey, peerKey);
            }),
    ];
}
