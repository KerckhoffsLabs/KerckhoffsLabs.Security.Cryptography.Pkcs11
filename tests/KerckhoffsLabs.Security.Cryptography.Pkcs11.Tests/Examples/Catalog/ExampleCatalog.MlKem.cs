using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/ml-kem.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] MlKemCases() =>
    [
        new(Name(nameof(MlKemExamples), nameof(MlKemExamples.MlKemReceiveAesKey)), [typeof(MLKemPkcs11)],
            [CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            AssertMlKemReceiveAesKey, Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.DecapsulationNeedsValueLen(b)),
    ];

    private static void AssertMlKemReceiveAesKey(IPkcs11Backend backend)
    {
        if (!backend.SupportsMlKem) Assert.Skip("The backend cannot operate ML-KEM.");
        if (!MLKem.IsSupported) Assert.Skip("ML-KEM is not supported by this platform's BCL (the sender side).");
        using Pkcs11Session session = backend.OpenSession();
        (Pkcs11Key tokenKey, byte[] senderKey) = MlKemExamples.MlKemReceiveAesKey(session);
        using (tokenKey)
        {
            // The sender encrypts with its copy of the shared secret; the token decrypts with its own.
            using var atSender = new AesGcm(senderKey, 16);
            byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
            atSender.Encrypt(nonce, Message, ciphertext, tag);
            using var onToken = new AesGcmPkcs11(tokenKey, 16);
            byte[] decrypted = new byte[ciphertext.Length];
            onToken.Decrypt(nonce, ciphertext, tag, decrypted);
            Assert.Equal(Message, decrypted);
        }
    }
}
