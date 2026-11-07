using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

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
                (byte[] signature, byte[] publicKey, byte[] generatedPublicKey) = GenerateAndUseMlDsaKey(b, checkAttributes: true);
                Assert.Equal(generatedPublicKey, publicKey);
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, signature, generatedPublicKey));
            },
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.MlDsaSign)), [typeof(MLDsaPkcs11)],
            [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA], ExampleBackend.Kryoptic,
            b =>
            {
                if (!b.SupportsMlDsa) Assert.Skip("The backend cannot operate ML-DSA.");
                (byte[] signature, byte[] publicKey, _) = GenerateAndUseMlDsaKey(b, checkAttributes: false);
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL; the token side ran.");
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, signature, publicKey));
                Assert.False(MlDsaExamples.MlDsaVerifyWithBcl([.. Message, 0], signature, publicKey));
            },
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.BclMlDsaSign)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL.");
                (byte[] signature, byte[] publicKey) = MlDsaExamples.BclMlDsaSign(Message);
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, signature, publicKey));
                Assert.False(MlDsaExamples.MlDsaVerifyWithBcl([.. Message, 0], signature, publicKey));
            }),
        new(Name(nameof(MlDsaExamples), nameof(MlDsaExamples.MlDsaVerifyWithBcl)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!MLDsa.IsSupported) Assert.Skip("ML-DSA is not supported by this platform's BCL.");
                using MLDsa bcl = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                Assert.True(MlDsaExamples.MlDsaVerifyWithBcl(Message, bcl.SignData(Message), bcl.ExportMLDsaPublicKey()));
            }),
    ];

    // The generation example provisions the key pair; the signing example opens it by label.
    private static (byte[] Signature, byte[] PublicKey, byte[] GeneratedPublicKey) GenerateAndUseMlDsaKey(
        IPkcs11Backend backend, bool checkAttributes)
    {
        (byte[], byte[], byte[]) result = default;
        WithGeneratedKey(backend, label =>
        {
            using SecurePin pin = UserPin(backend);
            byte[] generated = MlDsaExamples.GenerateMlDsaKey(backend.LibraryPath, backend.TokenLabel, pin, label);
            if (checkAttributes)
            {
                AssertGeneratedKey(backend, label, CKO.CKO_PRIVATE_KEY, CKA.CKA_SIGN);
                AssertGeneratedKey(backend, label, CKO.CKO_PUBLIC_KEY, CKA.CKA_VERIFY);
            }
            (byte[] signature, byte[] publicKey) = MlDsaExamples.MlDsaSign(backend.LibraryPath, backend.TokenLabel, pin, label, Message);
            result = (signature, publicKey, generated);
        });
        return result;
    }
}
