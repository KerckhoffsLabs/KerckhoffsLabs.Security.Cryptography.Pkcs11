using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/rc2.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11005 // RC2Pkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] Rc2Cases() =>
    [
        new(Name(nameof(Rc2Examples), nameof(Rc2Examples.Rc2DecryptLegacyRecord)), [typeof(RC2Pkcs11)], [CKM.CKM_RC2_CBC_PAD],
            // NSS is the only CI backend that runs RC2. It loads with module parameters and its crypto token
            // takes no login, so the example takes both as optional, and the test passes them NSS's way.
            ExampleBackend.Nss,
            b => AssertLegacyCbc(b, CKK.CKK_RC2, 16, 8, RC2.Create,
                (label, iv, ciphertext) =>
                {
                    using SecurePin? pin = b.RequiresUserLogin ? UserPin(b) : null;
                    Pkcs11LibraryOptions? options = b is NssBackendFixture
                        ? new Pkcs11LibraryOptions { ModuleParameters = Settings.NssModuleParameters }
                        : null;
                    return Rc2Examples.Rc2DecryptLegacyRecord(b.LibraryPath, b.TokenLabel, pin, label, iv, ciphertext, options);
                },
                key => new RC2Pkcs11(key)),
            Unsupported: ExampleGates.SecondModuleInstance),
        new(Name(nameof(Rc2Examples), nameof(Rc2Examples.BclRc2DecryptLegacyRecord)), [], [], ExampleBackend.Nss,
            _ => AssertBclLegacyCbc(16, RC2.Create, Rc2Examples.BclRc2DecryptLegacyRecord)),
    ];
#pragma warning restore KLPKCS11005
}
