using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/sha-2.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] Sha2Cases() =>
    [
        new(Name(nameof(Sha2Examples), nameof(Sha2Examples.Sha2OnToken)), [typeof(SHA256Pkcs11), typeof(SHA384Pkcs11), typeof(SHA512Pkcs11)],
            [CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b =>
            {
                Assert.Equal(Sha2Examples.BclSha2(Message), Sha2Examples.Sha2OnToken(b.LibraryPath, b.TokenLabel, Message));
                AssertFixtureLibraryStillWorks(b);
            },
            LoadsModule: true),
        new(Name(nameof(Sha2Examples), nameof(Sha2Examples.BclSha2)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                byte[][] digests = Sha2Examples.BclSha2("abc"u8.ToArray());
                Assert.Equal(Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), digests[0]); // FIPS 180 "abc"
                Assert.Equal([48, 64], digests[1..].Select(d => d.Length));
            }),
    ];
}
