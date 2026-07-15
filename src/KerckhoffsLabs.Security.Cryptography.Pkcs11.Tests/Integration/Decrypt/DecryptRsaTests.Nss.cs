using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>Cross-backend port of the SoftHSM2 RSA decrypt integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class DecryptRsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault() => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
