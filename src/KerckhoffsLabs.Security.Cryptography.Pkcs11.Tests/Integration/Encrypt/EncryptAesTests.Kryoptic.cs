using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>AES encrypt (CBC-PAD round-trip + ECB gate) tests against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class EncryptAesTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesCbcPad_ProducesCiphertext()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesCbcPad_RoundTrips()
        => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_ThrowsCryptoPolicyViolationException_ByDefault()
        => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue()
        => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
