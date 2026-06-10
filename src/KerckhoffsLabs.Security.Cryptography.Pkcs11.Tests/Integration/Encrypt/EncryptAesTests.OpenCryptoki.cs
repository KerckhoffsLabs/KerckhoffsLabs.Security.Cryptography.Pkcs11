using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Cross-backend port of the SoftHSM2 AES encrypt integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class EncryptAesTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void AesCbcPad_ProducesCiphertext() => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [ConditionalFact(nameof(Available))]
    public void AesCbcPad_RoundTrips() => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault() => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue() => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
