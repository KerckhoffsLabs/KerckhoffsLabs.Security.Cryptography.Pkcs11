using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Cross-backend port of the SoftHSM2 RSA encrypt integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class EncryptRsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault() => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
