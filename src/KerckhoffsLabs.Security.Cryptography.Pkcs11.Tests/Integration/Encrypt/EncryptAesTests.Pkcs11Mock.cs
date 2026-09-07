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

    // pkcs11-mock's C_GetMechanismList never advertises CKM_AES_CBC_PAD (see class remarks above) —
    // a fixed characteristic of the vendored mock shim's C source, not a per-host capability, so a
    // constant condition is appropriate here (flip it if pkcs11-mock is ever extended). A static
    // [Fact(Skip = "...")] (flagged by xUnit1004) hard-disables the test with no named, auditable
    // gate; [ConditionalFact] ties it to this property instead, matching every other permanently-off
    // capability gate in this suite (e.g. NssBackendFixture.SupportsRc2Ecb).
    public static bool SupportsAesCbcPad => false;

    // Crypto-correctness: needs a backend that actually implements AES-CBC-PAD.
    [ConditionalFact(nameof(SupportsAesCbcPad))]
    public void AesCbcPad_ProducesCiphertext_Mock()
        => EncryptAesTestCases.Assert_AesCbcPad_ProducesCiphertext(_backend);

    [ConditionalFact(nameof(SupportsAesCbcPad))]
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
