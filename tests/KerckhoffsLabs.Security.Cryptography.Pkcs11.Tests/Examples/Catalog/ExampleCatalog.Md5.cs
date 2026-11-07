using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/md5.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11001 // MD5Pkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] Md5Cases() =>
    [
        new(Name(nameof(Md5Examples), nameof(Md5Examples.Md5ChecksumForLegacyProtocol)), [typeof(MD5Pkcs11)], [CKM.CKM_MD5],
            ExampleBackend.SoftHsm2,
            b =>
            {
                Assert.Equal(Md5Examples.BclMd5(Message), Md5Examples.Md5ChecksumForLegacyProtocol(b.LibraryPath, b.TokenLabel, Message));
                AssertFixtureLibraryStillWorks(b);

                // Without the example's lease, the default policy refuses the same hash.
                using Pkcs11Session s = b.OpenSession();
                using var md5 = new MD5Pkcs11(s);
                Assert.Throws<CryptoPolicyViolationException>(() => md5.ComputeHash(Message));
            },
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(Md5Examples), nameof(Md5Examples.BclMd5)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Convert.FromHexString("900150983cd24fb0d6963f7d28e17f72"), Md5Examples.BclMd5("abc"u8.ToArray()))), // RFC 1321
    ];
#pragma warning restore KLPKCS11001
}
