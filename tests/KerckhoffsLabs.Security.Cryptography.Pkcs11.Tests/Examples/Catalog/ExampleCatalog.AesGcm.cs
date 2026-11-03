using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/aes-gcm.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] AesGcmCases() =>
    [
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.AesGcmEncryptDecrypt)), [typeof(AesGcmPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.Equal(Message, AesGcmExamples.AesGcmEncryptDecrypt(s, Message, Header))),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.BclAesGcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, AesGcmExamples.BclAesGcmEncryptDecrypt(Message, Header))),
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.AesGcmDetectsTampering)), [typeof(AesGcmPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.True(AesGcmExamples.AesGcmDetectsTampering(s, Message))),
            Unsupported: ExampleGates.ClassicAesGcm),
    ];
}
