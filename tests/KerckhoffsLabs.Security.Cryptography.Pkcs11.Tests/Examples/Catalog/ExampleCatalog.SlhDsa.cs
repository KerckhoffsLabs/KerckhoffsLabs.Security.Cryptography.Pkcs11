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
            b => WithSession(b, s =>
            {
                if (!b.SupportsSlhDsa) Assert.Skip("The backend cannot operate SLH-DSA.");
                (byte[] signature, byte[] publicKey) = SlhDsaExamples.SlhDsaSign(s, Message);
                if (!SlhDsa.IsSupported) Assert.Skip("SLH-DSA is not supported by this platform's BCL; the token side ran.");
                using SlhDsa verifier = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, publicKey);
                Assert.True(verifier.VerifyData(Message, signature));
            })),
    ];
#pragma warning restore SYSLIB5006
}
