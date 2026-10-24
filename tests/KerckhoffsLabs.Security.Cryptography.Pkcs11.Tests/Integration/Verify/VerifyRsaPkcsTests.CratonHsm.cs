using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

[Collection("CratonHsm")]
public sealed class VerifyRsaPkcsTests_CratonHsm(CratonHsmBackendFixture f)
{
    private readonly CratonHsmBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}
