using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA-OAEP with a label over BouncyHsm — thin wrapper over <see cref="EncryptRsaOaepLabelTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class EncryptRsaOaepLabelTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OaepWithLabel_RoundTrips() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithLabel_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OaepWithWrongLabel_FailsToDecrypt() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithWrongLabel_FailsToDecrypt(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.NullOaepLabelRefusalAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm takes a NULL OAEP label behind a length as the empty label")]
    public void OaepNullLabelWithLength_IsRefused() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepNullLabelWithLength_IsRefused(_backend);
}
