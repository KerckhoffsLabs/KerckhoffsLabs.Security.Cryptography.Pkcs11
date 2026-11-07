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
            AssertMlKemReceiveAesKey, NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.DecapsulationNeedsValueLen(b) ?? ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(MlKemExamples), nameof(MlKemExamples.BclMlKemReceive)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!MLKem.IsSupported) Assert.Skip("ML-KEM is not supported by this platform's BCL.");
                (byte[] receiverSecret, byte[] senderSecret) = MlKemExamples.BclMlKemReceive();
                Assert.Equal(32, receiverSecret.Length);
                Assert.Equal(senderSecret, receiverSecret);
            }),
    ];

    private static void AssertMlKemReceiveAesKey(IPkcs11Backend backend)
    {
        if (!backend.SupportsMlKem) Assert.Skip("The backend cannot operate ML-KEM.");
        if (!MLKem.IsSupported) Assert.Skip("ML-KEM is not supported by this platform's BCL (the sender side).");
        // The sender encrypts with its copy of the shared secret, and the token decrypts with its own: the
        // message comes back only if both hold the same secret.
        using (SecurePin pin = UserPin(backend))
            Assert.Equal(Message, MlKemExamples.MlKemReceiveAesKey(backend.LibraryPath, backend.TokenLabel, pin, Message));
        AssertFixtureLibraryStillWorks(backend);
    }
}
