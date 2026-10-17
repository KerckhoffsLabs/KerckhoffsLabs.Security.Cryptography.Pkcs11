using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 RSA PKCS#1 sign gate integration tests, run against BouncyHsm.</summary>
[Collection("BouncyHsm")]
public sealed class SignRsaPkcsTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignRsaPkcs1V15_GatedByDefault() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
