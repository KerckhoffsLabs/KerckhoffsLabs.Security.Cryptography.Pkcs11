using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/ecdsa.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] EcdsaCases() =>
    [
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.GenerateEcdsaKey)), [],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithGeneratedKey(b, label =>
            {
                using SecurePin pin = UserPin(b);
                byte[] spki = EcdsaExamples.GenerateEcdsaKey(b.LibraryPath, b.TokenLabel, pin, label);
                AssertGeneratedKey(b, label, CKO.CKO_PRIVATE_KEY, CKA.CKA_SIGN);
                AssertGeneratedKey(b, label, CKO.CKO_PUBLIC_KEY, CKA.CKA_VERIFY);
                (byte[] signature, _) = EcdsaExamples.SignP256(b.LibraryPath, b.TokenLabel, pin, label, Message);
                // The exported public key verifies what the opened pair signed: they are the same pair.
                using ECDsa verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(spki, out _);
                Assert.True(verifier.VerifyData(Message, signature, HashAlgorithmName.SHA256));
            }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.SignP256)), [typeof(ECDsaPkcs11)],
            [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            b => WithProvisionedKey(b,
                (s, label) => s.GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256, label, persistOnToken: b.SupportsTokenObjects),
                label =>
                {
                    using SecurePin pin = UserPin(b);
                    (byte[] signature, ECParameters publicKey) = EcdsaExamples.SignP256(b.LibraryPath, b.TokenLabel, pin, label, Message);
                    Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, publicKey));
                    Assert.False(EcdsaExamples.VerifyWithBcl([.. Message, 0], signature, publicKey));
                }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.BclSignP256)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                (byte[] signature, ECParameters publicKey) = EcdsaExamples.BclSignP256(Message);
                Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, publicKey));
                Assert.False(EcdsaExamples.VerifyWithBcl([.. Message, 0], signature, publicKey));
            }),
        new(Name(nameof(EcdsaExamples), nameof(EcdsaExamples.VerifyWithBcl)), [], [], ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                using ECDsa bcl = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256);
                Assert.True(EcdsaExamples.VerifyWithBcl(Message, signature, bcl.ExportParameters(false)));
            }),
    ];
}
