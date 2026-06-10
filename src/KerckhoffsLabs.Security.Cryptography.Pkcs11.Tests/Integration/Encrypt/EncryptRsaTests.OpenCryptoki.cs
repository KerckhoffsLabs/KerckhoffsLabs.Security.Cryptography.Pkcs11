using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Cross-backend port of the SoftHSM2 RSA encrypt integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class EncryptRsaTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault() => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
