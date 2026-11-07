using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/aes-ccm.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] AesCcmCases() =>
    [
        new(Name(nameof(AesCcmExamples), nameof(AesCcmExamples.AesCcmEncryptDecrypt)), [typeof(AesCcmPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CCM], ExampleBackend.Kryoptic,
            b => WithProvisionedKey(b,
                (s, label) => s.GenerateAesKey(256, label, persistOnToken: b.SupportsTokenObjects),
                label =>
                {
                    using SecurePin pin = UserPin(b);
                    Assert.Equal(Message, AesCcmExamples.AesCcmEncryptDecrypt(b.LibraryPath, b.TokenLabel, pin, label, Message, Header));
                }),
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(AesCcmExamples), nameof(AesCcmExamples.BclAesCcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!AesCcm.IsSupported) Assert.Skip("AES-CCM is not supported on this platform.");
                Assert.Equal(Message, AesCcmExamples.BclAesCcmEncryptDecrypt(Message, Header));
            }),
    ];
}
