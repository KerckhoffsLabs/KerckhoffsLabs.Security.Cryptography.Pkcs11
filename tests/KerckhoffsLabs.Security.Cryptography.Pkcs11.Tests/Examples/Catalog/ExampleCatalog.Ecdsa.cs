using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/ecdsa.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] EcdsaCases() =>
    [
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.SignP256)), [typeof(ECDsaPkcs11)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                (byte[] signature, ECParameters publicKey) = EcdsaExamples.SignP256(s, Message);
                Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, publicKey));
                Assert.False(EcdsaExamples.VerifyWithBcl([.. Message, 0], signature, publicKey));
            })),
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.BclSignP256)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                (byte[] signature, ECParameters publicKey) = EcdsaExamples.BclSignP256(Message);
                Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, publicKey));
                Assert.False(EcdsaExamples.VerifyWithBcl([.. Message, 0], signature, publicKey));
            }),
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.VerifyWithBcl)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                using ECDsa bcl = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256);
                Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, bcl.ExportParameters(false)));
            }),
    ];
}
