using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA verify test, run against NSS. Generates the key
/// pair on the token, so it exercises on-token keygen + sign + verify (tamper rejection). Gated on the
/// live mechanism list (CKM_EDDSA from NSS 3.125).
/// </summary>
[Collection("Nss")]
public sealed class VerifyEdDsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ed25519_RejectsTamperedData()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("NSS: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
        VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
    }
}
