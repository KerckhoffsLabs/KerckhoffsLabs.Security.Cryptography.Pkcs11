using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignEdDsaContext over BouncyHsm — thin wrapper over <see cref="SignEdDsaContextTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SignEdDsaContextTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ed25519ctx_WithContext_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ctx_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ed25519ph_Prehash_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ph_Prehash_RoundTrips(_backend);
}
