using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/rc2.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11005 // RC2Pkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] Rc2Cases() =>
    [
        new(Name(nameof(Rc2Examples), nameof(Rc2Examples.Rc2DecryptLegacyRecord)), [typeof(RC2Pkcs11)], [CKM.CKM_RC2_CBC_PAD],
            ExampleBackend.Nss,
            b => WithSession(b, s => AssertLegacyCbc(s, CKK.CKK_RC2, 16, 8, RC2.Create, Rc2Examples.Rc2DecryptLegacyRecord,
                key => new RC2Pkcs11(key)))),
        new(Name(nameof(Rc2Examples), nameof(Rc2Examples.BclRc2DecryptLegacyRecord)), [], [], ExampleBackend.Nss,
            _ => AssertBclLegacyCbc(16, RC2.Create, Rc2Examples.BclRc2DecryptLegacyRecord)),
    ];
#pragma warning restore KLPKCS11005
}
