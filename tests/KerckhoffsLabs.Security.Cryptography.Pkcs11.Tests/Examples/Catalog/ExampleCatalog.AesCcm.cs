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
            b => WithSession(b, s => Assert.Equal(Message, AesCcmExamples.AesCcmEncryptDecrypt(s, Message, Header)))),
        new(Name(nameof(AesCcmExamples), nameof(AesCcmExamples.BclAesCcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!AesCcm.IsSupported) Assert.Skip("AES-CCM is not supported on this platform.");
                Assert.Equal(Message, AesCcmExamples.BclAesCcmEncryptDecrypt(Message, Header));
            }),
    ];
}
