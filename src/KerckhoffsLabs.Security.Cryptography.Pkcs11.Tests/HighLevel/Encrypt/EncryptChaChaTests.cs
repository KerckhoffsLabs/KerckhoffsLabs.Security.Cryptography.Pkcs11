using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

/// <summary>
/// Shared test logic for ChaCha20-Poly1305 high-level helpers.
/// </summary>
internal static class EncryptChaChaTestCases
{
    private static readonly byte[] ChaCha20Key32 = new byte[32]
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };

    private static readonly byte[] ValidNonce12 = new byte[12]
    {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
    };

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
            ObjectHandle key = keyHandle;

            Assert.Throws<ArgumentException>(() =>
                session.EncryptChaCha20Poly1305(key, badNonce, plaintext));
        }
        finally
        {
            if (keyHandle != null)
                session.DestroyObject(keyHandle);
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
/// ChaCha20 tests against pkcs11-mock. All tests are marked [ConditionalFact(false)] because
/// pkcs11-mock's C_OpenSession returns CKR_SLOT_ID_INVALID with our function-list path,
/// and also because the mock predates PKCS#11 v3.0 (no ChaCha20-Poly1305 mechanism).
/// These scenarios require SoftHSM v3+.
/// </summary>
[Collection("Mock")]
public sealed class EncryptChaChaTests_Mock
{
    // MockSessionNotUsable = false causes all [ConditionalFact] tests to be reported as Skipped.
    public static bool MockSessionNotUsable => false;

    private readonly MockBackendFixture _backend;
    public EncryptChaChaTests_Mock(MockBackendFixture f) { _backend = f; }

    [ConditionalFact(nameof(MockSessionNotUsable))]
    public void ChaCha20_RejectsWrongNonceLength_Mock()
        => EncryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    [ConditionalFact(nameof(MockSessionNotUsable))]
    public void ChaCha20_RoundTrip_Mock()
        => EncryptChaChaTestCases.Assert_RoundTrip(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class EncryptChaChaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public EncryptChaChaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RejectsWrongNonceLength_SoftHsm()
        => EncryptChaChaTestCases.Assert_RejectsWrongNonceLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ChaCha20_RoundTrip_SoftHsm()
        => EncryptChaChaTestCases.Assert_RoundTrip(_backend);
}
