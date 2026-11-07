using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/aes.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] AesModeCases() =>
    [
        new(Name(nameof(AesModeExamples), nameof(AesModeExamples.GenerateArchiveKey)), [],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CBC_PAD], ExampleBackend.SoftHsm2,
            b => WithGeneratedKey(b, label =>
            {
                using SecurePin pin = UserPin(b);
                AesModeExamples.GenerateArchiveKey(b.LibraryPath, b.TokenLabel, pin, label);
                AssertGeneratedKey(b, label, CKO.CKO_SECRET_KEY, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
                Assert.Equal(Message, AesModeExamples.CbcPadUnderReviewedPolicy(b.LibraryPath, b.TokenLabel, pin, label, Message));
            }),
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(AesModeExamples), nameof(AesModeExamples.CbcPadUnderReviewedPolicy)), [typeof(AesPkcs11)],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CBC_PAD], ExampleBackend.SoftHsm2,
            AssertCbcPadUnderReviewedPolicy, NeedsUserLogin: true, Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(AesModeExamples), nameof(AesModeExamples.BclCbcPad)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, AesModeExamples.BclCbcPad(Message))),
    ];

    private static void AssertCbcPadUnderReviewedPolicy(IPkcs11Backend backend)
    {
        WithProvisionedKey(backend,
            (s, label) => s.GenerateAesKey(256, label, persistOnToken: backend.SupportsTokenObjects),
            label =>
            {
                using SecurePin pin = UserPin(backend);
                Assert.Equal(Message, AesModeExamples.CbcPadUnderReviewedPolicy(backend.LibraryPath, backend.TokenLabel, pin, label, Message));
            },
            key =>
            {
                // Without the example's policy step, the default Recommended policy refuses the same call.
                using var aes = new AesPkcs11(key);
                Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(Message, new byte[16], PaddingMode.PKCS7));
            });
    }
}
