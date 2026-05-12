using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Decrypt;

/// <summary>
/// Shared test logic for AES-GCM decryption edge cases.
/// Argument-validation tests run on both backends (managed checks fire before P/Invoke).
/// AEAD-integrity tests (tampered tag, wrong IV) are SoftHsm-only: the mock does not
/// authenticate ciphertext.
/// </summary>
internal static class DecryptAesGcmTestCases
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
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
    };

    private static readonly byte[] AltIv12 = new byte[12]
    {
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
    };

    /// <summary>
    /// ciphertextAndTag shorter than 16 bytes must be rejected before P/Invoke.
    /// </summary>
    internal static void Assert_RejectsTooShortCiphertext(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                // 15 bytes — one short of the minimum 16-byte tag.
                byte[] tooShort = new byte[15];

                Assert.Throws<ArgumentException>(() =>
                    session.DecryptAesGcm(keyHandle, ValidIv12, tooShort));
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

    /// <summary>
    /// IV that is not exactly 12 bytes must be rejected before P/Invoke.
    /// </summary>
    internal static void Assert_RejectsWrongIvLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] badIv = new byte[8]; // must be 12
                byte[] ciphertextAndTag = new byte[32]; // plausible size

                Assert.Throws<ArgumentException>(() =>
                    session.DecryptAesGcm(keyHandle, badIv, ciphertextAndTag));
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

    /// <summary>
    /// Encrypt a message, flip the last byte of the tag, then verify that decryption
    /// throws <see cref="Pkcs11Exception"/> (authentication failure). Requires a real
    /// AES-GCM implementation — SoftHsm-only.
    /// </summary>
    internal static void Assert_TamperedTagThrows(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM tamper test payload.");
                byte[] ciphertextAndTag = session.EncryptAesGcm(keyHandle, ValidIv12, plaintext);

                // Flip the last byte of the authentication tag.
                ciphertextAndTag[^1] ^= 0xFF;

                Assert.Throws<Pkcs11Exception>(() =>
                    session.DecryptAesGcm(keyHandle, ValidIv12, ciphertextAndTag));
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

    /// <summary>
    /// Encrypt with IV1, then attempt decryption with IV2. The authentication tag is
    /// computed over the IV, so the decryption must fail. Requires real AES-GCM —
    /// SoftHsm-only.
    /// </summary>
    internal static void Assert_WrongIvThrows(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM wrong-IV test.");
                byte[] ciphertextAndTag = session.EncryptAesGcm(keyHandle, ValidIv12, plaintext);

                // Decrypt with a different IV — must fail authentication.
                Assert.Throws<Pkcs11Exception>(() =>
                    session.DecryptAesGcm(keyHandle, AltIv12, ciphertextAndTag));
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
/// AES-GCM decryption tests against pkcs11-mock.
/// Argument-validation checks fire in managed code before any P/Invoke and run
/// unconditionally. AEAD-integrity tests (tampered tag, wrong IV) are SoftHsm-only
/// because the mock does not validate authentication tags.
/// </summary>
[Collection("Mock")]
public sealed class DecryptAesGcmTests_Mock
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend;
    public DecryptAesGcmTests_Mock(MockBackendFixture f) { _backend = f; }

    [Fact]
    public void AesGcm_RejectsTooShortCiphertext_Mock()
        => DecryptAesGcmTestCases.Assert_RejectsTooShortCiphertext(_backend);

    [Fact]
    public void AesGcm_RejectsWrongIvLength_Mock()
        => DecryptAesGcmTestCases.Assert_RejectsWrongIvLength(_backend);

    // AEAD-integrity tests require real GCM — SoftHsm only.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_TamperedTag_Throws_Mock()
        => DecryptAesGcmTestCases.Assert_TamperedTagThrows(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_WrongIv_Throws_Mock()
        => DecryptAesGcmTestCases.Assert_WrongIvThrows(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class DecryptAesGcmTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public DecryptAesGcmTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_RejectsTooShortCiphertext_SoftHsm()
        => DecryptAesGcmTestCases.Assert_RejectsTooShortCiphertext(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_RejectsWrongIvLength_SoftHsm()
        => DecryptAesGcmTestCases.Assert_RejectsWrongIvLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_TamperedTag_Throws_SoftHsm()
        => DecryptAesGcmTestCases.Assert_TamperedTagThrows(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_WrongIv_Throws_SoftHsm()
        => DecryptAesGcmTestCases.Assert_WrongIvThrows(_backend);
}
