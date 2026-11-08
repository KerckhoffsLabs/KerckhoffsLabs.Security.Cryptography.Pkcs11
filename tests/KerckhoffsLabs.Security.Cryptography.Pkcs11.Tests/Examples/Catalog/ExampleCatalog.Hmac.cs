using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/hmac.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] HmacCases() =>
    [
        new(Name(nameof(HmacExamples), nameof(HmacExamples.GenerateHmacKey)), [],
            [CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA256_HMAC], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            // The generation example stores the key on the token; the HMAC example then opens it by its label.
            b => WithGeneratedKey(b, label =>
            {
                using SecurePin pin = UserPin(b);
                HmacExamples.GenerateHmacKey(b.LibraryPath, b.TokenLabel, pin, label);
                AssertGeneratedKey(b, label, CKO.CKO_SECRET_KEY, CKA.CKA_SIGN, CKA.CKA_VERIFY);
                byte[] tag = HmacExamples.HmacSha256(b.LibraryPath, b.TokenLabel, pin, label, Message);
                Assert.Equal(32, tag.Length);
                Assert.Equal(tag, HmacExamples.HmacSha256(b.LibraryPath, b.TokenLabel, pin, label, Message));
            }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(HmacExamples), nameof(HmacExamples.HmacSha256)), [typeof(HMACPkcs11)], [CKM.CKM_SHA256_HMAC],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b =>
            {
                // A known key, imported under a label, so the token's HMAC can be compared with the BCL's.
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                WithProvisionedKey(b,
                    (s, label) =>
                    {
                        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
                            .Label(label).OnToken(b.SupportsTokenObjects).Value(raw).Sign().Verify().Build();
                        return s.ImportKey(template);
                    },
                    label =>
                    {
                        using SecurePin pin = UserPin(b);
                        Assert.Equal(HmacExamples.BclHmacSha256(raw, Message), HmacExamples.HmacSha256(b.LibraryPath, b.TokenLabel, pin, label, Message));
                    });
            },
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(HmacExamples), nameof(HmacExamples.BclHmacSha256)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                Assert.Equal(HMACSHA256.HashData(raw, Message), HmacExamples.BclHmacSha256(raw, Message));
            }),
    ];
}
