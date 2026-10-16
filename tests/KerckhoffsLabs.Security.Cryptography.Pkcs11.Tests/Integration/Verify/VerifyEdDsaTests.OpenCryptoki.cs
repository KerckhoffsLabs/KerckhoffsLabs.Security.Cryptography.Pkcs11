using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA verify test, run against opencryptoki. Generates the key
/// pair on the token, so it exercises on-token keygen + sign + verify (tamper rejection). Gated on the
/// live mechanism list.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class VerifyEdDsaTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ed25519_RejectsTamperedData()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("opencryptoki: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
        VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
    }
}
