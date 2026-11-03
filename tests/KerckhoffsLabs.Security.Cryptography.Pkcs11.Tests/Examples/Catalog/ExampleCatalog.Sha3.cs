using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/sha-3.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] Sha3Cases() =>
    [
        new(Name(nameof(Sha3Examples), nameof(Sha3Examples.Sha3OnToken)), [typeof(SHA3_256Pkcs11), typeof(SHA3_384Pkcs11), typeof(SHA3_512Pkcs11)],
            [CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512], ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                byte[][] onToken = Sha3Examples.Sha3OnToken(s, Message);
                if (!SHA3_256.IsSupported) Assert.Skip("SHA-3 is not supported by this platform's BCL; the token side ran.");
                Assert.Equal([SHA3_256.HashData(Message), SHA3_384.HashData(Message), SHA3_512.HashData(Message)], onToken);
            })),
    ];
}
