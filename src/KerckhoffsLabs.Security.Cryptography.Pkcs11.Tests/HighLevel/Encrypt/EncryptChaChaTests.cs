using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

/// <summary>
/// Shared test logic for ChaCha20-Poly1305 high-level helpers.
/// </summary>
internal static class EncryptChaChaTestCases
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
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
    ];

    internal static void Assert_RejectsWrongNonceLength(IPkcs11Backend backend)
    {
        // Nonce-length validation fires in managed code before C_EncryptInit,
        // but a session must still be opened to import the key.
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
            byte[] plaintext = new byte[16];
            ObjectHandle key = keyHandle.Value;

            Assert.Throws<ArgumentException>(() =>
                session.EncryptChaCha20Poly1305(key, badNonce, plaintext));
        }
        finally
        {
            if (keyHandle.HasValue)
                session.DestroyObject(keyHandle.Value);
            session.CloseSession();
        }
    }

    internal static void Assert_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateChaCha20Key(session, ChaCha20Key32);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("ChaCha20-Poly1305 round-trip test.");
                byte[] aad = System.Text.Encoding.UTF8.GetBytes("aad-for-chacha");

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
/// ChaCha20 tests against pkcs11-mock.
/// Nonce-length validation fires in managed code before C_EncryptInit and runs
/// unconditionally (the test body already handles the case where the mock rejects the
/// ChaCha20 key type via SkipTestException).
/// Round-trip requires CKM_CHACHA20_POLY1305, which the mock does not recognise —
/// that test stays SoftHsm-only.
/// </summary>
[Collection("Mock")]
public sealed class EncryptChaChaTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    // Argument-validation: nonce check fires in C# before any P/Invoke.
    [Fact]
    public void ChaCha20_RejectsWrongNonceLength_Mock()
        => EncryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    // Crypto-correctness: mock doesn't implement ChaCha20-Poly1305.
    [Fact(Skip = "Mock does not implement CKM_CHACHA20_POLY1305.")]
    public void ChaCha20_RoundTrip_Mock()
        => EncryptChaChaTestCases.Assert_RoundTrip(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class EncryptChaChaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsChaCha20KeyType => SoftHsmBackendFixture.SoftHsmSupportsChaCha20KeyType;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RejectsWrongNonceLength_SoftHsm()
        => EncryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    public void ChaCha20_RoundTrip_SoftHsm()
        => EncryptChaChaTestCases.Assert_RoundTrip(_backend);
}
