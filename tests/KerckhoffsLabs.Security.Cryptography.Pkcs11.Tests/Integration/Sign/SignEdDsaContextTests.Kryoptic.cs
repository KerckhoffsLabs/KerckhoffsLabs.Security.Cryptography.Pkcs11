using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignEdDsaContext over Kryoptic — thin wrapper over <see cref="SignEdDsaContextTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SignEdDsaContextTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ed25519ctx_WithContext_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ctx_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ed25519ph_Prehash_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ph_Prehash_RoundTrips(_backend);
}
