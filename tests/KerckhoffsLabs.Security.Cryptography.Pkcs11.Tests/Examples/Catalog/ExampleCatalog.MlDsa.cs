using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/ml-dsa.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] MlDsaCases() =>
    [
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.GenerateMlDsaKey)), [],
            [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA], ExampleBackend.Kryoptic,
            b =>
            {
                if (!b.SupportsMlDsa) Assert.Skip("The backend cannot operate ML-DSA.");
                byte[] publicKey = AssertGenerationExample(b, MlDsaExamples.GenerateMlDsaKey, [CKA.CKA_SIGN], [CKA.CKA_VERIFY]);
                Assert.Equal(1952, publicKey.Length); // an ML-DSA-65 public key (FIPS 204, Table 2)
            },
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.MlDsaSign)), [typeof(MLDsaPkcs11)],
            [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA], ExampleBackend.Kryoptic,
            b =>
            {
                if (!b.SupportsMlDsa) Assert.Skip("The backend cannot operate ML-DSA.");
                (byte[] signature, byte[] publicKey) = GenerateAndSignWithPair(b, MlDsaExamples.GenerateMlDsaKey, MlDsaExamples.MlDsaSign);
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, signature, publicKey));
                Assert.False(MlDsaExamples.MlDsaVerifyWithBcl([.. Message, 0], signature, publicKey));
            },
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.BclMlDsaSign)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL.");
                (byte[] signature, byte[] publicKey) = MlDsaExamples.BclMlDsaSign(Message);
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, signature, publicKey));
                Assert.False(MlDsaExamples.MlDsaVerifyWithBcl([.. Message, 0], signature, publicKey));
            }),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.MlDsaVerifyWithBcl)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL.");
                using MLDsa bcl = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, bcl.SignData(Message), bcl.ExportMLDsaPublicKey()));
            }),
    ];
}
