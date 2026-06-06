using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

[Collection("SoftHsm")]
public sealed class VerifyRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}
