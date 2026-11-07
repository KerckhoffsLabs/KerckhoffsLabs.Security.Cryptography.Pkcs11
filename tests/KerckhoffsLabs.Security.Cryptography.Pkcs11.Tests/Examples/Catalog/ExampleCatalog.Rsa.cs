using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/rsa.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] RsaCases() =>
    [
        new(Name(nameof(RsaExamples), nameof(RsaExamples.SignPss)), [typeof(RSAPkcs11)],
            [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithProvisionedKey(b,
                (s, label) => s.GenerateRsaSigningKeyPair(3072, label, persistOnToken: b.SupportsTokenObjects),
                label =>
                {
                    using SecurePin pin = UserPin(b);
                    (byte[] signature, RSAParameters publicKey) = RsaExamples.SignPss(b.LibraryPath, b.TokenLabel, pin, label, Message);
                    Assert.True(RsaExamples.VerifyPssWithBcl(Message, signature, publicKey));
                    Assert.False(RsaExamples.VerifyPssWithBcl([.. Message, 0], signature, publicKey));
                }),
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.VerifyPssWithBcl)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                using RSA bcl = RSA.Create(3072);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                Assert.True(RsaExamples.VerifyPssWithBcl(Message, signature, bcl.ExportParameters(false)));
            }),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.SignPkcs1v15)), [typeof(RSAPkcs11)],
            [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithSession(b, s =>
            {
                using Pkcs11Key key = s.GenerateRsaSigningKeyPair(3072);
                (byte[] signature, RSAParameters publicKey) = RsaExamples.SignPkcs1v15(key, Message);
                using RSA bcl = RSA.Create(publicKey);
                Assert.True(bcl.VerifyData(Message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            })),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.OaepEncryptDecrypt)), [typeof(RSAPkcs11)],
            [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithProvisionedKey(b,
                (s, label) => s.GenerateRsaKeyTransportKeyPair(3072, label, persistOnToken: b.SupportsTokenObjects),
                label =>
                {
                    using SecurePin pin = UserPin(b);
                    Assert.Equal(Message, RsaExamples.OaepEncryptDecrypt(b.LibraryPath, b.TokenLabel, pin, label, Message));
                }),
            NeedsUserLogin: true,
            Unsupported: b => b is SoftHsmBackendFixture && SoftHsmBackendFixture.IsV240Leg
                ? "SoftHSM 2.5 implements RSA-OAEP with SHA-1 only"
                : ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.BclSignPss)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                (byte[] signature, RSAParameters publicKey) = RsaExamples.BclSignPss(Message);
                Assert.True(RsaExamples.VerifyPssWithBcl(Message, signature, publicKey));
            }),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.BclSignPkcs1v15)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                (byte[] signature, RSAParameters publicKey) = RsaExamples.BclSignPkcs1v15(Message);
                using RSA verifier = RSA.Create(publicKey);
                Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }),
        new(Name(nameof(RsaExamples), nameof(RsaExamples.BclOaepEncryptDecrypt)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(Message, RsaExamples.BclOaepEncryptDecrypt(Message))),
    ];
}
