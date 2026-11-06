using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignEdDsaContext over opencryptoki — thin wrapper over <see cref="SignEdDsaContextTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SignEdDsaContextTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ed25519ctx_WithContext_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ctx_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ed25519ph_Prehash_RoundTrips() => SignEdDsaContextTestCases.Assert_Ed25519ph_Prehash_RoundTrips(_backend);
}
