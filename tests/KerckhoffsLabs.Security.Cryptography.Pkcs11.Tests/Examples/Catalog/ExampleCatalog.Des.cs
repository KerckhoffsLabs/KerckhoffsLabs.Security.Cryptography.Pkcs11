using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/des.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11003 // DESPkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] DesCases() =>
    [
        new(Name(nameof(DesExamples), nameof(DesExamples.DesDecryptLegacyRecord)), [typeof(DESPkcs11)], [CKM.CKM_DES_CBC_PAD],
            // opencryptoki is the CI backend that both runs single DES and takes a login, which the example
            // does. NSS runs DES too, but its crypto token takes no login: the example skips there.
            ExampleBackend.OpenCryptoki,
            b => AssertLegacyCbc(b, CKK.CKK_DES, 8, 8, DES.Create,
                (label, iv, ciphertext) =>
                {
                    using SecurePin pin = UserPin(b);
                    return DesExamples.DesDecryptLegacyRecord(b.LibraryPath, b.TokenLabel, pin, label, iv, ciphertext);
                },
                key => new DESPkcs11(key)),
            NeedsUserLogin: true,
            Unsupported: b => b is SoftHsmBackendFixture
                ? "SoftHSM advertises single DES, but its OpenSSL needs the legacy provider to run it"
                : ExampleGates.SecondModuleInstance(b)),
        new(Name(nameof(DesExamples), nameof(DesExamples.BclDesDecryptLegacyRecord)), [], [], ExampleBackend.Nss,
            _ => AssertBclLegacyCbc(8, DES.Create, DesExamples.BclDesDecryptLegacyRecord)),
    ];
#pragma warning restore KLPKCS11003
}
