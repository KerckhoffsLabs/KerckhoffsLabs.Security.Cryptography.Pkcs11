using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// AES test class for pkcs11-mock. Gate-enforcement tests run unconditionally:
/// <c>InsecureOperationException</c> is thrown in managed code before any P/Invoke call, so no real
/// crypto is required. Crypto-correctness tests (round-trip, ciphertext-produces) are SoftHsm-only:
/// the mock only recognises CKM_AES_CBC (not CKM_AES_CBC_PAD) and returns handle 1 (DATA) from
/// CreateObject, whereas its C_EncryptInit requires handle 2 (SECRET_KEY).
/// </summary>
[Collection("Mock")]
public sealed class EncryptAesTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    // Crypto-correctness: needs a backend that actually implements AES-CBC-PAD.
    [Fact(Skip = "Mock does not implement CKM_AES_CBC_PAD.")]
    public void AesCbcPad_ProducesCiphertext_Mock()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [Fact(Skip = "Mock does not implement CKM_AES_CBC_PAD.")]
    public void AesCbcPad_RoundTrip_Mock()
        => EncryptAesTestCases.Assert_AesCbcPad_RoundTrips(_backend);

    // Gate-enforcement: InsecureOperationException fires in C# before C_EncryptInit.
    [Fact]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_Mock()
        => EncryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact]
    public void AesEcb_AllowedWhenAllowInsecureTrue_Mock()
        => EncryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
