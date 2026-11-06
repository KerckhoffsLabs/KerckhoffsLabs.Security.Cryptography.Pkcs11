using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignHashMlDsa over Kryoptic — thin wrapper over <see cref="SignHashMlDsaTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SignHashMlDsaTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void HashMlDsaSha256_RoundTrips() => SignHashMlDsaTestCases.Assert_HashMlDsaSha256_RoundTrips(_backend);
}
