using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>AES encrypt (CBC-PAD round-trip + ECB gate) tests against SoftHSM2.</summary>
[Collection("SoftHsm")]
public sealed class EncryptAesTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesCbcPad_ProducesCiphertext_SoftHsm()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesCbcPad_RoundTrips_SoftHsm()
        => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue_SoftHsm()
        => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
