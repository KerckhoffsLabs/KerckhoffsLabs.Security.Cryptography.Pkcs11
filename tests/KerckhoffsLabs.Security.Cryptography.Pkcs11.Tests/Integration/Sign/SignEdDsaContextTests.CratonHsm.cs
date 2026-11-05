using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignEdDsaContext over Craton HSM — thin wrapper over <see cref="SignEdDsaContextTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class SignEdDsaContextTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.EdDsaParamsAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM ignores CK_EDDSA_PARAMS and signs plain Ed25519")]
    public void Ed25519ctx_WithContext_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ctx_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.EdDsaParamsAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM ignores CK_EDDSA_PARAMS and signs plain Ed25519")]
    public void Ed25519ph_Prehash_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ph_Prehash_RoundTrips(_backend);
}
