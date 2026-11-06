using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignHashMlDsa over BouncyHsm — thin wrapper over <see cref="SignHashMlDsaTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SignHashMlDsaTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashMlDsaSha256_RoundTrips() => SignHashMlDsaTestCases.Assert_HashMlDsaSha256_RoundTrips(_backend);
}
