using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors;

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
    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Raw CKM_CHACHA20 is gated by default (no integrity protection — see Pkcs11SessionCore's
    // CryptoPolicyViolationException for this mechanism), which is exactly what these tests exercise, so
    // The AllowInsecure policy is required.
    private static void WithImportedKey(IPkcs11Backend backend, byte[] rawKey, Action<Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_CHACHA20);
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"chacha20-raw-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(session, label); }
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

    // === Counter boundaries (Wycheproof chacha20_counter_test.json) =============================
    // pkcs11-check 0.3.0's refreshed Wycheproof pin brought these (https://github.com/mingulov/pkcs11-check, sources.toml).
    // Each starts a few blocks from the end of the block counter. The ChaCha20-IETF group has a 32-bit counter and a
    // 96-bit nonce: CK_CHACHA20_PARAMS as above. The XChaCha20 group has a 64-bit counter: CKM_CHACHA20 with a 64-bit
    // counter and a 64-bit nonce, under the HChaCha20 subkey of the vector's key and its 192-bit nonce's first 16 bytes,
    // with the last 8 as the nonce. Its counters start at 2^32 - 2 and 2^32 - 1, so the counter's low word carries into
    // its high word, and at 2^64 - 2 and 2^64 - 1.
    //
    // A valid case ends on or before the counter's last value, and the token must give Wycheproof's ciphertext: one that
    // drops the carry repeats an earlier block's keystream. An invalid case needs a block past the last value, so the
    // token must refuse it rather than wrap the counter to 0 and reuse block 0's keystream. The 0-byte cases are left
    // out: they encrypt no block.
    //
    // refusesBecause declares a backend that refuses a valid case (its counter and nonce layout, or a block it wrongly
    // counts as past the end), and why: the case skips with that reason, and fails once the backend encrypts it, so the
    // declaration goes. encryptsPastTheLastBlockBecause declares a backend that encrypts an invalid case: the case
    // skips with that reason, and fails once the backend refuses it.
    public static TheoryData<int> CounterBoundaryCases =>
        [.. WycheproofVectors.ChaCha20Counter.Where(c => c.Message.Length > 0).Select(c => c.TcId)];

    internal static void Assert_CounterBoundary_Wycheproof(
        IPkcs11Backend backend, int tcId, string? refusesBecause = null, string? encryptsPastTheLastBlockBecause = null)
    {
        backend.RequireMechanism(CKM.CKM_CHACHA20);
        WycheproofVectors.StreamCipherCase v = WycheproofVectors.ChaCha20Counter.Single(c => c.TcId == tcId);
        (byte[] key, byte[] nonce) = v.Algorithm switch
        {
            "ChaCha20-IETF" => (v.Key, v.Iv),
            "XChaCha20" => (HChaCha20.DeriveSubkey(v.Key, v.Iv.AsSpan(0, 16)), v.Iv[16..]),
            _ => throw new ArgumentOutOfRangeException(nameof(tcId), v.Algorithm, "Not a ChaCha20 variant CKM_CHACHA20 computes."),
        };
        var mechanism = new Mechanism(CKM.CKM_CHACHA20, new CkmChaCha20Params(v.InitialCounter, v.CounterSize, nonce, 8 * nonce.Length));
        string vector = $"Wycheproof tcId {v.TcId} ({v.Comment})";

        WithImportedKey(backend, key, chacha20 =>
        {
            byte[]? ciphertext = null;
            CKR? refused = null;
            try { ciphertext = chacha20.Encrypt(mechanism, v.Message); }
            catch (Pkcs11Exception ex) { refused = ex.ReturnValue; }

            // PKCS#11 leaves the 64-bit counter / 64-bit nonce layout optional: NSS keeps the counter in 32 bits and
            // Kryoptic takes only the RFC 8439 layout, and both answer CKR_MECHANISM_PARAM_INVALID. A refusal at
            // counter 0 as well says the layout is not offered, which tells nothing about the counter's end.
            if (refused == CKR.CKR_MECHANISM_PARAM_INVALID && v.CounterSize == 64 && RefusesCounterLayout(chacha20, nonce))
                Assert.Skip($"{vector}: the backend does not take a 64-bit block counter with a {8 * nonce.Length}-bit nonce.");

            if (v.Valid)
            {
                if (refusesBecause is not null)
                {
                    if (refused is not null)
                        Assert.Skip(refusesBecause);
                    Assert.Fail($"{vector}: the backend now encrypts it; drop its refusesBecause (\"{refusesBecause}\").");
                }
                Assert.True(refused is null, $"{vector}: refused with {refused}, though its last block is within the counter's range.");
                Assert.True(v.Ciphertext.AsSpan().SequenceEqual(ciphertext),
                    $"{vector}: the ciphertext differs from Wycheproof's; a dropped carry or a wrapped counter repeats a block's keystream.");
                return;
            }

            if (encryptsPastTheLastBlockBecause is not null)
            {
                if (ciphertext is not null)
                    Assert.Skip(encryptsPastTheLastBlockBecause);
                Assert.Fail($"{vector}: the backend now refuses it ({refused}); drop its encryptsPastTheLastBlockBecause (\"{encryptsPastTheLastBlockBecause}\").");
            }
            Assert.True(ciphertext is null,
                $"{vector}: encrypted {v.Message.Length} bytes, past the {v.CounterSize}-bit counter's last block, where it must refuse rather than wrap the counter and reuse a block's keystream.");
        });
    }

    private static bool RefusesCounterLayout(Pkcs11Key chacha20, byte[] nonce)
    {
        var atZero = new Mechanism(CKM.CKM_CHACHA20, new CkmChaCha20Params(new byte[8], 64, nonce, 8 * nonce.Length));
        try
        {
            chacha20.Encrypt(atZero, new byte[1]);
            return false;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_PARAM_INVALID)
        {
            return true;
        }
    }
}
