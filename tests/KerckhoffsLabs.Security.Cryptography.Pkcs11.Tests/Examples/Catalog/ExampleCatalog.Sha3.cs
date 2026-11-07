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
                Assert.Equal(Sha3Examples.BclSha3(Message), onToken);
            })),
        new(Name(nameof(Sha3Examples), nameof(Sha3Examples.BclSha3)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                byte[][]? digests = Sha3Examples.BclSha3("abc"u8.ToArray());
                if (digests is null) Assert.Skip("SHA-3 is not supported by this platform's BCL.");
                Assert.Equal(Convert.FromHexString("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), digests[0]); // FIPS 202 "abc"
                Assert.Equal([48, 64], digests[1..].Select(d => d.Length));
            }),
    ];
}
