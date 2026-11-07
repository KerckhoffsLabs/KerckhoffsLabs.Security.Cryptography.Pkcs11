using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/triple-des.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11004 // TripleDESPkcs11, named for coverage and as the unleased adapter
    private static ExampleCase[] TripleDesCases() =>
    [
        new(Name(nameof(TripleDesExamples), nameof(TripleDesExamples.TripleDesDecryptLegacyArchive)), [typeof(TripleDESPkcs11)],
            [CKM.CKM_DES3_CBC_PAD], ExampleBackend.SoftHsm2,
            b => WithSession(b, s => AssertLegacyCbc(s, CKK.CKK_DES3, 24, 8, TripleDES.Create, TripleDesExamples.TripleDesDecryptLegacyArchive,
                key => new TripleDESPkcs11(key)))),
        new(Name(nameof(TripleDesExamples), nameof(TripleDesExamples.BclTripleDesDecryptLegacyArchive)), [], [], ExampleBackend.SoftHsm2,
            _ => AssertBclLegacyCbc(24, TripleDES.Create, TripleDesExamples.BclTripleDesDecryptLegacyArchive)),
    ];
#pragma warning restore KLPKCS11004
}
