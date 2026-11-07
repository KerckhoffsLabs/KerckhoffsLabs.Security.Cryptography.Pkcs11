using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/sha-1.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11002 // SHA1Pkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] Sha1Cases() =>
    [
        new(Name(nameof(Sha1Examples), nameof(Sha1Examples.Sha1ForLegacyProtocol)), [typeof(SHA1Pkcs11)], [CKM.CKM_SHA_1],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                Assert.Equal(Sha1Examples.BclSha1(Message), Sha1Examples.Sha1ForLegacyProtocol(s, Message));
                using var sha1 = new SHA1Pkcs11(s);
                Assert.Throws<CryptoPolicyViolationException>(() => sha1.ComputeHash(Message));
            })),
        new(Name(nameof(Sha1Examples), nameof(Sha1Examples.BclSha1)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Convert.FromHexString("a9993e364706816aba3e25717850c26c9cd0d89d"), Sha1Examples.BclSha1("abc"u8.ToArray()))), // FIPS 180 "abc"
    ];
#pragma warning restore KLPKCS11002
}
