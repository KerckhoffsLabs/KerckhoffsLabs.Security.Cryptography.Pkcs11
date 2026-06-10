using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>Cross-backend port of the SoftHSM2 AES decrypt integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class DecryptAesTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault() => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue() => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
