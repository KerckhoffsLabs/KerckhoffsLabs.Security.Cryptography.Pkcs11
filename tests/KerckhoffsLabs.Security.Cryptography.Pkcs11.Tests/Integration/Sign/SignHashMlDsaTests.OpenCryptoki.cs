using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignHashMlDsa over opencryptoki — thin wrapper over <see cref="SignHashMlDsaTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SignHashMlDsaTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void HashMlDsaSha256_RoundTrips() => SignHashMlDsaTestCases.Assert_HashMlDsaSha256_RoundTrips(_backend);
}
