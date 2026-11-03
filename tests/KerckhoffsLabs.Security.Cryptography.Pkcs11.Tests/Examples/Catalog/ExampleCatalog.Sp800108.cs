using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/sp800-108.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] Sp800108Cases() =>
    [
        new(Name(nameof(Sp800108Examples), nameof(Sp800108Examples.Sp800108DeriveAesKey)), [typeof(SP800108HmacCounterKdfPkcs11)],
            [CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SHA256_HMAC, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                byte[] kdk = RandomNumberGenerator.GetBytes(32);
                using Pkcs11Key kdkKey = ImportDeriveKey(s, kdk);
                using Pkcs11Key derived = Sp800108Examples.Sp800108DeriveAesKey(kdkKey, "orders"u8.ToArray(), "tenant-42"u8.ToArray());
                AssertSameAesKey(derived, Sp800108Examples.BclSp800108(kdk, "orders"u8.ToArray(), "tenant-42"u8.ToArray()));
            }),
            Unsupported: ExampleGates.ClassicAesGcm),
        new(Name(nameof(Sp800108Examples), nameof(Sp800108Examples.BclSp800108)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(32, Sp800108Examples.BclSp800108(new byte[32], [1], [2]).Length)),
    ];
}
