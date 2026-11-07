using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/pbkdf2.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] Pbkdf2Cases() =>
    [
        new(Name(nameof(Pbkdf2Examples), nameof(Pbkdf2Examples.Pbkdf2DeriveAesKey)), [typeof(Rfc2898DeriveBytesPkcs11)],
            // Kryoptic runs PBKDF2 and takes a login, which the example does (as do FreeHSM and wolfPKCS11).
            // NSS runs it too, but its crypto token takes no login: the example skips there.
            [CKM.CKM_PKCS5_PBKD2, CKM.CKM_AES_GCM], ExampleBackend.Kryoptic,
            b =>
            {
                byte[] salt = RandomNumberGenerator.GetBytes(16);
                using (var password = new SecurePassword("correct horse battery staple".AsSpan()))
                using (SecurePin pin = UserPin(b))
                    AssertDecryptsWith(Pbkdf2Examples.BclPbkdf2("correct horse battery staple"u8.ToArray(), salt),
                        Pbkdf2Examples.Pbkdf2DeriveAesKey(b.LibraryPath, b.TokenLabel, pin, password, salt, Message));
                AssertFixtureLibraryStillWorks(b);
            },
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(Pbkdf2Examples), nameof(Pbkdf2Examples.BclPbkdf2)), [], [], ExampleBackend.SoftHsm2,
            _ => Assert.Equal(
                Rfc2898DeriveBytes.Pbkdf2("pw"u8, new byte[16], 600_000, HashAlgorithmName.SHA256, 32),
                Pbkdf2Examples.BclPbkdf2("pw"u8.ToArray(), new byte[16]))),
    ];
}
