using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA sign tests, run against BouncyHsm. These generate the
/// EdDSA key pair on the token (CKM_EC_EDWARDS_KEY_PAIR_GEN), so the round-trip exercises on-token
/// keygen + sign + verify. Gated on the live mechanism list.
/// </summary>
[Collection("BouncyHsm")]
public sealed class SignEdDsaTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private void RequireEdDsa()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("BouncyHsm: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ed25519_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ed448_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
    }
}
