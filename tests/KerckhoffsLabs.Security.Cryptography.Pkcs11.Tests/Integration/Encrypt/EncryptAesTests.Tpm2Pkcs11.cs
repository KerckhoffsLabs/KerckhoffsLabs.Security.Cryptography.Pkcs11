using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>AES encrypt (CBC-PAD round-trip + ECB gate) tests against tpm2-pkcs11.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class EncryptAesTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;


    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void AesCbcPad_ProducesCiphertext()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void AesCbcPad_RoundTrips()
        => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void AesEcb_ThrowsCryptoPolicyViolationException_ByDefault()
        => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue()
        => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
