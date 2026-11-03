using System.Security.Cryptography;
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
            b => WithSession(b, s => Assert.Equal(
                [SHA256.HashData(Message), SHA384.HashData(Message), SHA512.HashData(Message)],
                Sha2Examples.Sha2OnToken(s, Message)))),
        new(Name(nameof(Sha2Examples), nameof(Sha2Examples.BclSha256)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(SHA256.HashData(Message), Sha2Examples.BclSha256(Message))),
    ];
}
