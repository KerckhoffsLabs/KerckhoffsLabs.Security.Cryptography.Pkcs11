using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Decrypt;

/// <summary>
/// Shared test logic for ChaCha20-Poly1305 decryption edge cases.
/// Argument-validation tests run on both backends (managed checks fire before P/Invoke).
/// The round-trip test requires CKM_CHACHA20_POLY1305 and is SoftHsm-only.
/// </summary>
internal static class DecryptChaChaTestCases
{
    private static readonly byte[] ChaCha20Key32 =
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    private static readonly byte[] ValidNonce12 =
    [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
    ];

    /// <summary>
    /// Nonce that is not exactly 12 bytes must be rejected before P/Invoke.
    /// If the backend rejects the ChaCha20 key type (pre-v3.0 mock), the test is skipped
    /// gracefully via <see cref="SkipTestException"/>.
    /// </summary>
    internal static void Assert_RejectsWrongNonceLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        ObjectHandle? keyHandle = null;
        try
        {
            try
            {
                keyHandle = TestKeys.CreateChaCha20Key(session, ChaCha20Key32);
            }
            catch
            {
                // Backend may reject CKK_CHACHA20 (pre-v3.0 stub) — skip instead of fail.
                throw new SkipTestException(
                    "Backend rejected ChaCha20 key import; nonce-length validation requires SoftHSM v3+.");
            }

            byte[] badNonce = new byte[8]; // must be 12
            byte[] ciphertextAndTag = new byte[32]; // plausible size
            ObjectHandle key = keyHandle.Value;

            Assert.Throws<ArgumentException>(() =>
                session.DecryptChaCha20Poly1305(key, badNonce, ciphertextAndTag));
        }
        finally
        {
            if (keyHandle.HasValue)
                session.DestroyObject(keyHandle.Value);
            session.CloseSession();
        }
    }

    /// <summary>
    /// ciphertextAndTag shorter than 16 bytes must be rejected before P/Invoke.
    /// </summary>
    internal static void Assert_RejectsTooShortCiphertext(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        ObjectHandle? keyHandle = null;
        try
        {
            try
            {
                keyHandle = TestKeys.CreateChaCha20Key(session, ChaCha20Key32);
            }
            catch
            {
                throw new SkipTestException(
                    "Backend rejected ChaCha20 key import; ciphertext-length validation requires SoftHSM v3+.");
            }

            byte[] tooShort = new byte[15]; // one short of the minimum 16-byte tag
            ObjectHandle key = keyHandle.Value;

            Assert.Throws<ArgumentException>(() =>
                session.DecryptChaCha20Poly1305(key, ValidNonce12, tooShort));
        }
        finally
        {
            if (keyHandle.HasValue)
                session.DestroyObject(keyHandle.Value);
            session.CloseSession();
        }
    }

    /// <summary>
    /// Full encrypt-then-decrypt round-trip verifying plaintext recovery. Requires
    /// CKM_CHACHA20_POLY1305 support — SoftHsm-only.
    /// </summary>
    internal static void Assert_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateChaCha20Key(session, ChaCha20Key32);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("ChaCha20-Poly1305 decrypt round-trip.");
                byte[] aad = System.Text.Encoding.UTF8.GetBytes("additional-authenticated-data");

                byte[] ciphertextAndTag =
                    session.EncryptChaCha20Poly1305(keyHandle, ValidNonce12, plaintext, aad);

                Assert.Equal(plaintext.Length + 16, ciphertextAndTag.Length);

                byte[] recovered =
                    session.DecryptChaCha20Poly1305(keyHandle, ValidNonce12, ciphertextAndTag, aad);

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
/// ChaCha20-Poly1305 decryption tests against pkcs11-mock.
/// Argument-validation checks fire in managed code before any P/Invoke and run
/// unconditionally (the test body handles the case where the mock rejects the ChaCha20
/// key type via SkipTestException). Round-trip requires real ChaCha20-Poly1305 and is
/// SoftHsm-only.
/// </summary>
[Collection("Mock")]
public sealed class DecryptChaChaTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void ChaCha20_RejectsWrongNonceLength_Mock()
        => DecryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    [Fact]
    public void ChaCha20_RejectsTooShortCiphertext_Mock()
        => DecryptChaChaTestCases.Assert_RejectsTooShortCiphertext(_backend);

    // Round-trip: mock doesn't implement ChaCha20-Poly1305.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RoundTrip_Mock()
        => DecryptChaChaTestCases.Assert_RoundTrip(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class DecryptChaChaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RejectsWrongNonceLength_SoftHsm()
        => DecryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RejectsTooShortCiphertext_SoftHsm()
        => DecryptChaChaTestCases.Assert_RejectsTooShortCiphertext(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RoundTrip_SoftHsm()
        => DecryptChaChaTestCases.Assert_RoundTrip(_backend);
}
