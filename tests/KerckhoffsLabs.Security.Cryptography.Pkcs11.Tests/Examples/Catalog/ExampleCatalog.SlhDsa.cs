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
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.SlhDsaSign)), [typeof(SlhDsaPkcs11)],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm,
            b =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                byte[] signature, publicKey;
                using (SecurePin pin = UserPin(b))
                    (signature, publicKey) = SlhDsaExamples.SlhDsaSign(b.LibraryPath, b.TokenLabel, pin, Message);
                AssertFixtureLibraryStillWorks(b);
                // A standard FIPS 205 signature: the BCL verifies it from the exported public key.
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                AssertSlhDsaVerifies(signature, publicKey);
            },
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.BclSlhDsaSign)), [], [], ExampleBackend.SoftHsm2,
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
