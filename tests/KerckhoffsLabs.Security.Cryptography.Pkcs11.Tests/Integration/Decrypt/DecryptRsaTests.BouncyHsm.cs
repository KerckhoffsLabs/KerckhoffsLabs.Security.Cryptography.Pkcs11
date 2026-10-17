using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>Cross-backend port of the SoftHSM2 RSA decrypt integration tests, run against BouncyHsm.</summary>
[Collection("BouncyHsm")]
public sealed class DecryptRsaTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault() => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
