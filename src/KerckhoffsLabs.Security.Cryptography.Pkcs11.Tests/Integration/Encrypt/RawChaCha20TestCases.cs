using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated raw CKM_CHACHA20 mechanism on purpose (the secure-defaults policy check is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// Real-backend coverage for the raw <c>CKM_CHACHA20</c> stream-cipher mechanism (PKCS#11 v3.0,
/// <see cref="CkmChaCha20Params"/>) — previously exercised only at the unit-marshalling level. RFC
/// 8439 defines ChaCha20-Poly1305's ciphertext as the plaintext XORed with the raw ChaCha20 keystream
/// starting at block counter 1 (block 0 is reserved for the one-time Poly1305 key), so the BCL's
/// <see cref="ChaCha20Poly1305"/> primitive doubles as an independent reference implementation for the
/// raw cipher: encrypting with it and discarding the tag yields exactly the bytes raw CKM_CHACHA20
/// must produce with an IETF (32-bit) block counter of 1 and the same key/nonce — a genuine
/// known-answer cross-check, not just "the call didn't throw". Kryoptic and NSS both implement
/// CKM_CHACHA20 for real (verified against their vendored sources); SoftHSM2 and opencryptoki
/// implement neither, so those skip via the live mechanism-list check.
/// </summary>
internal static class RawChaCha20TestCases
{
    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Raw CKM_CHACHA20 is gated by default (no integrity protection — see Pkcs11Session's
    // CryptoPolicyViolationException for this mechanism), which is exactly what these tests exercise, so
    // The AllowInsecure policy is required.
    private static void WithImportedKey(IPkcs11Backend backend, byte[] rawKey, Action<Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_CHACHA20);
        using var workspace = backend.OpenWorkspace();
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"chacha20-raw-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // PKCS#11 v3.0 CK_CHACHA20_PARAMS: little-endian block counter, IETF layout is 32-bit
    // counter / 96-bit nonce.
    private static Mechanism ChaCha20Mechanism(ReadOnlySpan<byte> nonce, uint blockCounter) =>
        new(CKM.CKM_CHACHA20, new CkmChaCha20Params(BitConverter.GetBytes(blockCounter), 32, nonce, 96));

    internal static void Assert_Encrypt_MatchesBclChaCha20Poly1305Keystream(IPkcs11Backend backend)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = Encoding.UTF8.GetBytes(
            "Raw ChaCha20's keystream must match RFC 8439's block-counter-1 convention.");

        byte[] expected = new byte[plaintext.Length];
        byte[] discardedTag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(key))
            bcl.Encrypt(nonce, plaintext, expected, discardedTag);

        WithImportedKey(backend, key, chacha20 =>
        {
            byte[] actual = chacha20.Encrypt(ChaCha20Mechanism(nonce, 1), plaintext);
            Assert.Equal(expected, actual);
        });
    }

    internal static void Assert_EncryptDecrypt_RoundTrips(IPkcs11Backend backend)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("Round trip through the same token, same block counter.");

        WithImportedKey(backend, key, chacha20 =>
        {
            byte[] ciphertext = chacha20.Encrypt(ChaCha20Mechanism(nonce, 0), plaintext);
            byte[] recovered = chacha20.Decrypt(ChaCha20Mechanism(nonce, 0), ciphertext);
            Assert.Equal(plaintext, recovered);
        });
    }

    // Raw CKM_CHACHA20 is an unauthenticated stream cipher: a wrong block counter (unlike a wrong
    // AEAD tag) never throws — it silently re-XORs with a different keystream and hands back garbage.
    // That absence of an integrity check is the whole reason the mechanism is gated by default, and
    // the gap CKM_CHACHA20_POLY1305 exists to close.
    internal static void Assert_Decrypt_WrongCounter_ProducesGarbageNotException(IPkcs11Backend backend)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("Raw CKM_CHACHA20 carries no authentication tag.");

        WithImportedKey(backend, key, chacha20 =>
        {
            byte[] ciphertext = chacha20.Encrypt(ChaCha20Mechanism(nonce, 0), plaintext);
            byte[] wrongCounterResult = chacha20.Decrypt(ChaCha20Mechanism(nonce, 1), ciphertext);
            Assert.NotEqual(plaintext, wrongCounterResult);
        });
    }
}
