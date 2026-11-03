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
            ExampleBackend.Nss,
            b => WithSession(b, s => AssertLegacyCbc(s, CKK.CKK_DES, 8, 8, DES.Create, DesExamples.DesDecryptLegacyRecord,
                key => new DESPkcs11(key))),
            Unsupported: b => b is SoftHsmBackendFixture
                ? "SoftHSM advertises single DES, but its OpenSSL needs the legacy provider to run it"
                : null),
    ];
#pragma warning restore KLPKCS11003
}
