using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/slh-dsa.md
internal static partial class ExampleCatalog
{
#pragma warning disable SYSLIB5006 // SlhDsa and SlhDsaPkcs11 are [Experimental] in .NET 10
    private static ExampleCase[] SlhDsaCases() =>
    [
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.GenerateSlhDsaKey)), [],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm | ExampleBackend.Kryoptic,
            b =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey, byte[] generatedPublicKey) = GenerateAndSignWithPair(b, SlhDsaExamples.GenerateSlhDsaKey, SlhDsaExamples.SlhDsaSign, checkAttributes: true);
                Assert.Equal(generatedPublicKey, publicKey);
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                AssertSlhDsaVerifies(signature, generatedPublicKey);
            },
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.SlhDsaSign)), [typeof(SlhDsaPkcs11)],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm | ExampleBackend.Kryoptic,
            b =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey, _) = GenerateAndSignWithPair(b, SlhDsaExamples.GenerateSlhDsaKey, SlhDsaExamples.SlhDsaSign, checkAttributes: false);
                // A standard FIPS 205 signature: the BCL verifies it from the exported public key.
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                AssertSlhDsaVerifies(signature, publicKey);
            },
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.BclSlhDsaSign)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL.");
                (byte[] signature, byte[] publicKey) = SlhDsaExamples.BclSlhDsaSign(Message);
                AssertSlhDsaVerifies(signature, publicKey);
            }),
    ];

    private static void AssertSlhDsaVerifies(byte[] signature, byte[] publicKey)
    {
        using SlhDsa verifier = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, publicKey);
        Assert.True(verifier.VerifyData(Message, signature));
        Assert.False(verifier.VerifyData((byte[])[.. Message, 0], signature));
    }
#pragma warning restore SYSLIB5006
}
