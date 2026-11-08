using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/chacha20-poly1305.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] ChaCha20Poly1305Cases() =>
    [
        new(Name(nameof(ChaCha20Poly1305Examples), nameof(ChaCha20Poly1305Examples.GenerateChaCha20Key)), [],
            [CKM.CKM_CHACHA20_KEY_GEN, CKM.CKM_CHACHA20_POLY1305], ExampleBackend.Kryoptic,
            b => WithGeneratedKey(b, label =>
            {
                using SecurePin pin = UserPin(b);
                ChaCha20Poly1305Examples.GenerateChaCha20Key(b.LibraryPath, b.TokenLabel, pin, label);
                AssertGeneratedKey(b, label, CKO.CKO_SECRET_KEY, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
            }),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(ChaCha20Poly1305Examples), nameof(ChaCha20Poly1305Examples.ChaCha20Poly1305EncryptDecrypt)),
            [typeof(ChaCha20Poly1305Pkcs11)], [CKM.CKM_CHACHA20_KEY_GEN, CKM.CKM_CHACHA20_POLY1305], ExampleBackend.Kryoptic,
            // The generation example provisions the key; this one opens it by label.
            b => GenerateAndUseChaCha20Key(b),
            NeedsUserLogin: true,
            LoadsModule: true),
        new(Name(nameof(ChaCha20Poly1305Examples), nameof(ChaCha20Poly1305Examples.BclChaCha20Poly1305EncryptDecrypt)), [], [],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            _ =>
            {
                if (!ChaCha20Poly1305.IsSupported) Assert.Skip("ChaCha20-Poly1305 is not supported on this platform.");
                Assert.Equal(Message, ChaCha20Poly1305Examples.BclChaCha20Poly1305EncryptDecrypt(Message, Header));
            }),
    ];

    private static void GenerateAndUseChaCha20Key(IPkcs11Backend backend) =>
        WithGeneratedKey(backend, label =>
        {
            using SecurePin pin = UserPin(backend);
            ChaCha20Poly1305Examples.GenerateChaCha20Key(backend.LibraryPath, backend.TokenLabel, pin, label);
            Assert.Equal(Message, ChaCha20Poly1305Examples.ChaCha20Poly1305EncryptDecrypt(
                backend.LibraryPath, backend.TokenLabel, pin, label, Message, Header));
        });
}
