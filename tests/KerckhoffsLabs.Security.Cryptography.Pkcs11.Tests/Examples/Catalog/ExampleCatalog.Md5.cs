using System.Security.Cryptography;
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
            b => WithSession(b, s =>
            {
                Assert.Equal(MD5.HashData(Message), Md5Examples.Md5ChecksumForLegacyProtocol(s, Message));
                using var md5 = new MD5Pkcs11(s);
                Assert.Throws<CryptoPolicyViolationException>(() => md5.ComputeHash(Message));
            })),
    ];
#pragma warning restore KLPKCS11001
}
