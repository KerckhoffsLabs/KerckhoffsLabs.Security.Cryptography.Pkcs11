using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA verify test, run against NSS. Generates the key
/// pair on the token, so it exercises on-token keygen + sign + verify (tamper rejection). Gated on the
/// live mechanism list.
/// </summary>
[Collection("Nss")]
public sealed class VerifyEdDsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // NSS's CKM_EDDSA needs a CK_EDDSA_PARAMS the shared bare-parameter case does not pass; skip.
    public static bool EdDsa => NssBackendFixture.EdDsaAvailable;

    [ConditionalFact(nameof(EdDsa))]
    public void Ed25519_RejectsTamperedData()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            throw new SkipTestException("NSS: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
        VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
    }
}
