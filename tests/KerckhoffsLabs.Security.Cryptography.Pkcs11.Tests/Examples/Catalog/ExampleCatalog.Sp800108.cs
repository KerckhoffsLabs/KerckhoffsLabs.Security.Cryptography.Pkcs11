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
            b =>
            {
                byte[] kdk = RandomNumberGenerator.GetBytes(32);
                WithProvisionedKey(b, (s, label) => ImportDeriveKey(b, s, label, kdk),
                    label =>
                    {
                        using SecurePin pin = UserPin(b);
                        AssertDecryptsWith(Sp800108Examples.BclSp800108(kdk, "orders"u8.ToArray(), "tenant-42"u8.ToArray()),
                            Sp800108Examples.Sp800108DeriveAesKey(
                                b.LibraryPath, b.TokenLabel, pin, label, "orders"u8.ToArray(), "tenant-42"u8.ToArray(), Message));
                    });
            },
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(Sp800108Examples), nameof(Sp800108Examples.BclSp800108)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(32, Sp800108Examples.BclSp800108(new byte[32], [1], [2]).Length)),
    ];
}
