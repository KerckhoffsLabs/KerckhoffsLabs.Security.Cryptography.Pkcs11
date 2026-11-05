using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignEdDsaContext over SoftHSM2 — thin wrapper over <see cref="SignEdDsaContextTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class SignEdDsaContextTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.EdDsaParamsAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "SoftHSM ignores CK_EDDSA_PARAMS and signs plain Ed25519 (SoftHSM #619)")]
    public void Ed25519ctx_WithContext_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ctx_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.EdDsaParamsAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "SoftHSM ignores CK_EDDSA_PARAMS and signs plain Ed25519 (SoftHSM #619)")]
    public void Ed25519ph_Prehash_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ph_Prehash_RoundTrips(_backend);
}
