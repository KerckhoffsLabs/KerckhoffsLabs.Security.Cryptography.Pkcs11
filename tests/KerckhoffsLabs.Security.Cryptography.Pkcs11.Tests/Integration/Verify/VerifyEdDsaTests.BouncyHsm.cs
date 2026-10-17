using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA verify test, run against BouncyHsm. Generates the key
/// pair on the token, so it exercises on-token keygen + sign + verify (tamper rejection). Gated on the
/// live mechanism list.
/// </summary>
[Collection("BouncyHsm")]
public sealed class VerifyEdDsaTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ed25519_RejectsTamperedData()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("BouncyHsm: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
        VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
    }
}
