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
        new(Name(nameof(HmacExamples), nameof(HmacExamples.GenerateHmacKey)), [typeof(HMACPkcs11)],
            [CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_SHA256_HMAC], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                using Pkcs11Key key = HmacExamples.GenerateHmacKey(s);
                byte[] tag = HmacExamples.HmacSha256(key, Message);
                Assert.Equal(32, tag.Length);
                Assert.Equal(tag, HmacExamples.HmacSha256(key, Message));
            })),
        new(Name(nameof(HmacExamples), nameof(HmacExamples.HmacSha256)), [typeof(HMACPkcs11)], [CKM.CKM_SHA256_HMAC],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                // A known key, imported, so the token's HMAC can be compared with the BCL's.
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(raw).Sign().Verify().Build();
                using Pkcs11Key key = s.ImportKey(template);
                Assert.Equal(HmacExamples.BclHmacSha256(raw, Message), HmacExamples.HmacSha256(key, Message));
            })),
        new(Name(nameof(HmacExamples), nameof(HmacExamples.BclHmacSha256)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                byte[] raw = RandomNumberGenerator.GetBytes(32);
                Assert.Equal(HMACSHA256.HashData(raw, Message), HmacExamples.BclHmacSha256(raw, Message));
            }),
    ];
}
