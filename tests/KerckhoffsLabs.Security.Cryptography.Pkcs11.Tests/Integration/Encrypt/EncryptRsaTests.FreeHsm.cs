using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA PKCS#1 v1.5 gate against FreeHSM.</summary>
[Collection("FreeHsm")]
public sealed class EncryptRsaTests_FreeHsm(FreeHsmBackendFixture f)
{
    private readonly FreeHsmBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
