using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/chacha20-poly1305.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] ChaCha20Poly1305Cases() =>
    [
        new(Name(nameof(ChaCha20Poly1305Examples), nameof(ChaCha20Poly1305Examples.ChaCha20Poly1305EncryptDecrypt)),
            [typeof(ChaCha20Poly1305Pkcs11)], [CKM.CKM_CHACHA20_KEY_GEN, CKM.CKM_CHACHA20_POLY1305], ExampleBackend.Kryoptic,
            b =>
            {
                using (SecurePin pin = UserPin(b))
                    Assert.Equal(Message, ChaCha20Poly1305Examples.ChaCha20Poly1305EncryptDecrypt(b.LibraryPath, b.TokenLabel, pin, Message, Header));
                AssertFixtureLibraryStillWorks(b);
            },
            NeedsUserLogin: true,
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(ChaCha20Poly1305Examples), nameof(ChaCha20Poly1305Examples.BclChaCha20Poly1305EncryptDecrypt)), [], [],
            ExampleBackend.SoftHsm2,
            _ =>
            {
                if (!ChaCha20Poly1305.IsSupported) Assert.Skip("ChaCha20-Poly1305 is not supported on this platform.");
                Assert.Equal(Message, ChaCha20Poly1305Examples.BclChaCha20Poly1305EncryptDecrypt(Message, Header));
            }),
    ];
}
