using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/slh-dsa.md
internal static partial class ExampleCatalog
{
#pragma warning disable SYSLIB5006 // SlhDsa and SlhDsaPkcs11 are [Experimental] in .NET 10
    private static ExampleCase[] SlhDsaCases() =>
    [
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.GenerateSlhDsaKey)), [],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm,
            b =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey, byte[] generatedPublicKey) = GenerateAndUseSlhDsaKey(b, checkAttributes: true);
                Assert.Equal(generatedPublicKey, publicKey);
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                AssertSlhDsaVerifies(signature, generatedPublicKey);
            },
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(SlhDsaExamples), nameof(SlhDsaExamples.SlhDsaSign)), [typeof(SlhDsaPkcs11)],
            [CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA], ExampleBackend.BouncyHsm,
            b =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey, _) = GenerateAndUseSlhDsaKey(b, checkAttributes: false);
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

    // The generation example provisions the key pair; the signing example opens it by label.
    private static (byte[] Signature, byte[] PublicKey, byte[] GeneratedPublicKey) GenerateAndUseSlhDsaKey(
        IPkcs11Backend backend, bool checkAttributes)
    {
        (byte[], byte[], byte[]) result = default;
        WithGeneratedKey(backend, label =>
        {
            using SecurePin pin = UserPin(backend);
            byte[] generated = SlhDsaExamples.GenerateSlhDsaKey(backend.LibraryPath, backend.TokenLabel, pin, label);
            if (checkAttributes)
            {
                AssertGeneratedKey(backend, label, CKO.CKO_PRIVATE_KEY, CKA.CKA_SIGN);
                AssertGeneratedKey(backend, label, CKO.CKO_PUBLIC_KEY, CKA.CKA_VERIFY);
            }
            (byte[] signature, byte[] publicKey) = SlhDsaExamples.SlhDsaSign(backend.LibraryPath, backend.TokenLabel, pin, label, Message);
            result = (signature, publicKey, generated);
        });
        return result;
    }

    private static void AssertSlhDsaVerifies(byte[] signature, byte[] publicKey)
    {
        using SlhDsa verifier = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, publicKey);
        Assert.True(verifier.VerifyData(Message, signature));
        Assert.False(verifier.VerifyData((byte[])[.. Message, 0], signature));
    }
#pragma warning restore SYSLIB5006
}
