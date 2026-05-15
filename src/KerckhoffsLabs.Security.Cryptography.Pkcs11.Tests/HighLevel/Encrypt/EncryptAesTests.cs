using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

/// <summary>
/// Shared test logic for AES-CBC, AES-CBC-PAD, and AES-ECB (gate) scenarios.
/// Concrete per-backend classes below wire up xUnit attributes.
/// </summary>
internal static class EncryptAesTestCases
{
    // 32-byte AES-256 key material used across all AES tests.
    private static readonly byte[] AesKey256 =
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    // 16-byte IV for CBC modes.
    private static readonly byte[] Iv16 =
    [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
        0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    ];

    internal static void Assert_AesCbcPad_ProducesCiphertext(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, PKCS#11 AES-CBC-PAD!");

                using var mechanism = new Mechanism(CKM.CKM_AES_CBC_PAD, Iv16);
                byte[] ciphertext = session.Encrypt(mechanism, keyHandle, plaintext);

                Assert.NotNull(ciphertext);
                Assert.True(ciphertext.Length > 0, "Expected non-empty ciphertext.");
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_AesCbcPad_RoundTrips(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Round-trip test for AES-CBC-PAD.");

                using var encMechanism = new Mechanism(CKM.CKM_AES_CBC_PAD, Iv16);
                byte[] ciphertext = session.Encrypt(encMechanism, keyHandle, plaintext);

                Assert.NotNull(ciphertext);
                Assert.True(ciphertext.Length > 0);

                using var decMechanism = new Mechanism(CKM.CKM_AES_CBC_PAD, Iv16);
                byte[] recovered = session.Decrypt(decMechanism, keyHandle, ciphertext);

                Assert.Equal(plaintext, recovered);
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_AesEcb_GatedByDefault(IPkcs11Backend backend)
    {
        // The InsecureOperationException guard fires before any P/Invoke call to C_Encrypt,
        // but a session must still be opened first.
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = new byte[16]; // must be block-aligned for ECB
                using var mechanism = new Mechanism(CKM.CKM_AES_ECB);

                Assert.Throws<InsecureOperationException>(() =>
                    session.Encrypt(mechanism, keyHandle, plaintext));
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_AesEcb_AllowedWithOptIn(IPkcs11Backend backend)
    {
        // With AllowInsecure = true the gate is bypassed; the backend accepts the call.
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = new byte[16];
                using var mechanism = new Mechanism(CKM.CKM_AES_ECB);

                // Must not throw InsecureOperationException.
                var ex = Record.Exception(() =>
                    session.Encrypt(mechanism, keyHandle, plaintext));

                // The backend may throw a Pkcs11Exception for other reasons, but must NOT
                // throw InsecureOperationException.
                Assert.False(ex is InsecureOperationException,
                    "Expected gate to be bypassed, but InsecureOperationException was still thrown.");
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// ---------------------------------------------------------------------------

/// <summary>
/// AES test class for pkcs11-mock.
/// Gate-enforcement tests run unconditionally: <see cref="InsecureOperationException"/>
/// is thrown in managed code before any P/Invoke call, so no real crypto is required.
/// Crypto-correctness tests (round-trip, ciphertext-produces) are SoftHsm-only: the mock
/// only recognises CKM_AES_CBC (not CKM_AES_CBC_PAD) and returns handle 1 (DATA) from
/// CreateObject, whereas its C_EncryptInit requires handle 2 (SECRET_KEY).
/// </summary>
[Collection("Mock")]
public sealed class EncryptAesTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

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

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

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
