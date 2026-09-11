using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>AES encrypt (CBC-PAD round-trip + ECB gate) tests against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class EncryptAesTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesCbcPad_ProducesCiphertext_Kryoptic()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesCbcPad_RoundTrips_Kryoptic()
        => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_Kryoptic()
        => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue_Kryoptic()
        => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
