using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/sp800-108.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] Sp800108Cases() =>
    [
        new(Name(nameof(Sp800108Examples), nameof(Sp800108Examples.GenerateKeyDerivationKey)), [],
            [CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SHA256_HMAC, CKM.CKM_AES_GCM],
            ExampleBackend.Kryoptic,
            b => WithGeneratedKey(b, label =>
            {
                (byte[] Nonce, byte[] Ciphertext, byte[] Tag) sealedMessage;
                using (SecurePin pin = UserPin(b))
                {
                    Sp800108Examples.GenerateKeyDerivationKey(b.LibraryPath, b.TokenLabel, pin, label);
                    AssertGeneratedKey(b, label, CKO.CKO_SECRET_KEY, CKA.CKA_DERIVE);
                    sealedMessage = Sp800108Examples.Sp800108DeriveAesKey(
                        b.LibraryPath, b.TokenLabel, pin, label, "orders"u8.ToArray(), "tenant-42"u8.ToArray(), Message);
                }
                // The same label and context derive the same key again from the stored master key.
                AssertDecryptsWithTokenKey(b, sealedMessage, s =>
                {
                    using Pkcs11Key master = s.OpenKey(label);
                    using var kdf = new SP800108HmacCounterKdfPkcs11(master, HashAlgorithmName.SHA256);
                    using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();
                    return kdf.DeriveKey("orders"u8.ToArray(), "tenant-42"u8.ToArray(), aesKey);
                });
            }),
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b), LoadsModule: true),
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
            Unsupported: b => ExampleGates.ClassicAesGcm(b), LoadsModule: true),
        new(Name(nameof(Sp800108Examples), nameof(Sp800108Examples.BclSp800108)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ => Assert.Equal(32, Sp800108Examples.BclSp800108(new byte[32], [1], [2]).Length)),
    ];
}
