using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA-OAEP with a label over NSS softoken — thin wrapper over <see cref="EncryptRsaOaepLabelTestCases"/>.</summary>
[Collection("Nss")]
public sealed class EncryptRsaOaepLabelTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void OaepWithLabel_RoundTrips() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithLabel_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void OaepWithWrongLabel_FailsToDecrypt() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithWrongLabel_FailsToDecrypt(_backend);
}
