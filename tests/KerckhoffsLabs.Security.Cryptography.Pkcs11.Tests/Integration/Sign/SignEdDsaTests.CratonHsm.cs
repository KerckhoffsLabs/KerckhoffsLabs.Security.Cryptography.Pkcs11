using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA sign tests, run against Craton HSM. The shared
/// <see cref="SignEdDsaTestCases"/> assertions gate on the live mechanism list via
/// <c>IPkcs11Backend.RequireMechanism</c>.</summary>
[Collection("CratonHsm")]
public sealed class SignEdDsaTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    // No Ed448: Craton HSM implements Ed25519 only (CKM_EDDSA key size 256) and refuses the curve with
    // CKR_CURVE_NOT_SUPPORTED.
}
