using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

[Collection("SoftHsm")]
public sealed class SignRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SignRsaPkcs1V15_GatedByDefault()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
