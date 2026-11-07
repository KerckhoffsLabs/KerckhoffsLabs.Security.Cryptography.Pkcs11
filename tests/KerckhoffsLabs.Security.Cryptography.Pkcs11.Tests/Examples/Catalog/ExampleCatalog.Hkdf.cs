using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/hkdf.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] HkdfCases() =>
    [
        new(Name(nameof(HkdfExamples), nameof(HkdfExamples.HkdfDeriveAesKey)), [typeof(HkdfPkcs11)],
            [CKM.CKM_HKDF_DERIVE, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            b =>
            {
                byte[] ikm = RandomNumberGenerator.GetBytes(32), salt = RandomNumberGenerator.GetBytes(32), info = "example"u8.ToArray();
                WithProvisionedKey(b, (s, label) => ImportDeriveKey(b, s, label, ikm),
                    label =>
                    {
                        using SecurePin pin = UserPin(b);
                        AssertDecryptsWith(HkdfExamples.BclHkdf(ikm, salt, info),
                            HkdfExamples.HkdfDeriveAesKey(b.LibraryPath, b.TokenLabel, pin, label, salt, info, Message));
                    });
            },
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(HkdfExamples), nameof(HkdfExamples.BclHkdf)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(32, HkdfExamples.BclHkdf(new byte[32], new byte[16], []).Length)),
    ];
}
