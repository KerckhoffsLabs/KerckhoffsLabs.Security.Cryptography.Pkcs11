using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA-OAEP with a label over Craton HSM — thin wrapper over <see cref="EncryptRsaOaepLabelTestCases"/>.</summary>
[Collection("CratonHsm")]
[ResetCratonHsmLogin]
public sealed class EncryptRsaOaepLabelTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void OaepWithLabel_RoundTrips() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithLabel_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void OaepWithWrongLabel_FailsToDecrypt() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithWrongLabel_FailsToDecrypt(_backend);
}
