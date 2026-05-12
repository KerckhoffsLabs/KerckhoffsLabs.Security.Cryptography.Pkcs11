using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

/// <summary>
/// Shared test logic for AES-GCM high-level helpers.
/// </summary>
internal static class EncryptAesGcmTestCases
{
    private static readonly byte[] AesKey256 = new byte[32]
    {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    };

    private static readonly byte[] ValidIv12 = new byte[12]
    {
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
    };

    internal static void Assert_RejectsWrongIvLength(IPkcs11Backend backend)
    {
        // IV validation fires in managed code before C_EncryptInit, but a session
        // must still be opened and a key imported first.
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] badIv = new byte[8]; // should be 12
                byte[] plaintext = new byte[16];

                Assert.Throws<ArgumentException>(() =>
                    session.EncryptAesGcm(keyHandle, badIv, plaintext));
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

    internal static void Assert_ProducesCiphertextOfExpectedLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = new byte[32];
                byte[] ciphertextAndTag = session.EncryptAesGcm(keyHandle, ValidIv12, plaintext);

                // Expect ciphertext + 16-byte tag.
                Assert.Equal(plaintext.Length + 16, ciphertextAndTag.Length);
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

    internal static void Assert_RoundTrip_WithAad(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM round-trip with AAD.");
                byte[] aad = System.Text.Encoding.UTF8.GetBytes("additional-authenticated-data");

                byte[] ciphertextAndTag = session.EncryptAesGcm(keyHandle, ValidIv12, plaintext, aad);
                Assert.Equal(plaintext.Length + 16, ciphertextAndTag.Length);

                byte[] recovered = session.DecryptAesGcm(keyHandle, ValidIv12, ciphertextAndTag, aad);
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
}

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// ---------------------------------------------------------------------------

/// <summary>
/// AES-GCM tests against pkcs11-mock.
/// IV-validation fires in managed code before C_EncryptInit and runs unconditionally.
/// Length and round-trip tests depend on real GCM semantics (tag appended) which the
/// mock does not implement — those stay SoftHsm-only.
/// </summary>
[Collection("Mock")]
public sealed class EncryptAesGcmTests_Mock
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend;
    public EncryptAesGcmTests_Mock(MockBackendFixture f) { _backend = f; }

    // Argument-validation: IV check fires in C# before any P/Invoke.
    [Fact]
    public void AesGcm_RejectsWrongIvLength_Mock()
        => EncryptAesGcmTestCases.Assert_RejectsWrongIvLength(_backend);

    // Crypto-correctness: mock returns DataLen bytes (no tag appended); assertion fails.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_ProducesCiphertextOfExpectedLength_Mock()
        => EncryptAesGcmTestCases.Assert_ProducesCiphertextOfExpectedLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_RoundTrip_WithAad_Mock()
        => EncryptAesGcmTestCases.Assert_RoundTrip_WithAad(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class EncryptAesGcmTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public EncryptAesGcmTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_RejectsWrongIvLength_SoftHsm()
        => EncryptAesGcmTestCases.Assert_RejectsWrongIvLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_ProducesCiphertextOfExpectedLength_SoftHsm()
        => EncryptAesGcmTestCases.Assert_ProducesCiphertextOfExpectedLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_RoundTrip_WithAad_SoftHsm()
        => EncryptAesGcmTestCases.Assert_RoundTrip_WithAad(_backend);
}
