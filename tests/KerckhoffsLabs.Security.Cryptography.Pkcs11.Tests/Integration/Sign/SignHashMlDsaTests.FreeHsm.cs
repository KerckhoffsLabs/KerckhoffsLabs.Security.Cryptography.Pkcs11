using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignHashMlDsa over FreeHSM — thin wrapper over <see cref="SignHashMlDsaTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class SignHashMlDsaTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HashMlDsaSha256_RoundTrips() => SignHashMlDsaTestCases.Assert_HashMlDsaSha256_RoundTrips(_backend);
}
