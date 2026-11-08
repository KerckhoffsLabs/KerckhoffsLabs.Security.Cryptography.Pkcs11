using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/aes-gcm.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] AesGcmCases() =>
    [
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.GenerateAesGcmKey)), [],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithGeneratedKey(b, label =>
            {
                using SecurePin pin = UserPin(b);
                AesGcmExamples.GenerateAesGcmKey(b.LibraryPath, b.TokenLabel, pin, label);
                AssertGeneratedKey(b, label, CKO.CKO_SECRET_KEY, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
                Assert.Equal(Message, AesGcmExamples.AesGcmEncryptDecrypt(b.LibraryPath, b.TokenLabel, pin, label, Message, Header));
            }),
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b), LoadsModule: true),
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.AesGcmEncryptDecrypt)), [typeof(AesGcmPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithProvisionedKey(b,
                (s, label) => s.GenerateAesKey(256, label, persistOnToken: b.SupportsTokenObjects),
                label =>
                {
                    using SecurePin pin = UserPin(b);
                    Assert.Equal(Message, AesGcmExamples.AesGcmEncryptDecrypt(b.LibraryPath, b.TokenLabel, pin, label, Message, Header));
                }),
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b), LoadsModule: true),
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.BclAesGcmEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ => Assert.Equal(Message, AesGcmExamples.BclAesGcmEncryptDecrypt(Message, Header))),
        new(Name(nameof(AesGcmExamples), nameof(AesGcmExamples.AesGcmDetectsTampering)), [typeof(AesGcmPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s => Assert.True(AesGcmExamples.AesGcmDetectsTampering(s, Message))),
            Unsupported: ExampleGates.ClassicAesGcm),
    ];
}
