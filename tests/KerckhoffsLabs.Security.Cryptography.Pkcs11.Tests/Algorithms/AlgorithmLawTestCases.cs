using System.Security.Cryptography;
using FsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms.PropertyTestSupport;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Laws the <c>Algorithms</c> adapters keep on their own, checked with FsCheck (<see cref="FsInputs"/>):
/// what the token seals it opens, what it signs it verifies, and it rejects any one-bit change to a sealed
/// message, a signature or a signed message. <see cref="BclDifferentialTestCases"/> compares the same
/// adapters with the BCL; these laws reach what that comparison cannot: the token's own decryption of its
/// own output, its verification, the rejection of tampered input, ML-KEM, and relations between outputs
/// that hold for any implementation (an HKDF or PBKDF2 output is a prefix of a longer one).
/// </summary>
/// <remarks>
/// <para>
/// No BCL computes a reference, so the laws also run on a token whose algorithm the host lacks. The adapters
/// still take only the tag sizes the host BCL does (16-byte AES-GCM tags only on macOS), and the in-process
/// managed token, which computes with the BCL, offers only what the host has.
/// Tampered input goes only to authenticated decryption and to verification, never to an unpadding or
/// key-unwrap path, so no token is handed malformed padding.
/// </para>
/// <para>
/// Theory parameters pick the algorithm and are gated before the law runs, on the mechanism the backend
/// advertises. The arbitraries pick everything else. Every symmetric key is imported fresh for its case,
/// so no key and IV pair repeats.
/// </para>
/// </remarks>
internal static partial class AlgorithmLawTestCases
{
    // === AEAD ==============================================================================

    private sealed record AeadMessage(byte[] Nonce, byte[] Plaintext, byte[] AssociatedData)
    {
        public override string ToString() =>
            $"nonce {Convert.ToHexString(Nonce)}, aad {Convert.ToHexString(AssociatedData)}, plaintext {Convert.ToHexString(Plaintext)}";
    }

    private delegate void AeadEncrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData);

    private delegate void AeadDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData);

    private static Arbitrary<AeadMessage> AeadMessages(int minNonce, int maxNonce) =>
        FsCheck.Fluent.Arb.Convert(
            FsInputs.Zip(FsInputs.Bytes(minNonce, maxNonce), FsInputs.Bytes(0, 1024), FsInputs.Bytes(0, 256)),
            t => new AeadMessage(t.Item1, t.Item2, t.Item3),
            m => (m.Nonce, m.Plaintext, m.AssociatedData));

    // AES-GCM under every key size, 96-bit nonce and tag size (12 to 16 bytes) the token takes.
    internal static void Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(IPkcs11Backend backend, int[]? keySizes = null, int[]? tagSizes = null)
    {
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        Arbitrary<byte[]> key = FsInputs.BytesOfLength(keySizes ?? [16, 24, 32]);
        Arbitrary<int> tag = FsInputs.OneOf(AdapterTagSizes(tagSizes ?? [16, 12, 13, 14, 15], AesGcmPkcs11.TagByteSizes));

        AssertAeadLaws(backend, CKK.CKK_AES, key, tag, AeadMessages(12, 12),
            (k, t) => new AesGcmPkcs11(k, t), a => a.Encrypt, a => a.Decrypt);
    }

    // AES-CCM under every key size, nonce size (7 to 13 bytes) and tag size the default policy allows.
    internal static void Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_CCM);

        AssertAeadLaws(backend, CKK.CKK_AES, FsInputs.BytesOfLength(16, 24, 32), FsInputs.OneOf(AdapterTagSizes([16, 8, 10, 12, 14], AesCcmPkcs11.TagByteSizes)), AeadMessages(7, 13),
            (k, t) => new AesCcmPkcs11(k, t), a => a.Encrypt, a => a.Decrypt);
    }

    internal static void Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_CHACHA20_POLY1305);

        AssertAeadLaws(backend, CKK.CKK_CHACHA20, FsInputs.BytesOfLength(32), FsInputs.OneOf(16), AeadMessages(12, 12),
            (k, _) => new ChaCha20Poly1305Pkcs11(k), a => a.Encrypt, a => a.Decrypt);
    }

    // The tag sizes the adapter takes, which are the host BCL's: 16 only for AES-GCM on macOS.
    private static int[] AdapterTagSizes(int[] wanted, KeySizes adapter)
    {
        int[] sizes = [.. wanted.Where(t => IsLegal(t, adapter))];
        RequireHost(sizes.Length > 0, "The adapter takes none of the tag sizes the token does on this host.");
        return sizes;
    }

    // The token opens its own sealed message to the plaintext, and refuses the message with any one bit
    // of the nonce, ciphertext, tag or associated data flipped: an AuthenticationTagMismatchException with
    // the destination cleared, or, from a module that reports a failed tag check with a generic code, the
    // module's Pkcs11Exception. Either way no plaintext comes back.
    private static void AssertAeadLaws<TAead>(
        IPkcs11Backend backend, CKK keyType, Arbitrary<byte[]> keys, Arbitrary<int> tagSizes, Arbitrary<AeadMessage> messages,
        Func<Pkcs11Key, int, TAead> create, Func<TAead, AeadEncrypt> encryptOf, Func<TAead, AeadDecrypt> decryptOf)
        where TAead : IDisposable
    {
        using var session = backend.OpenSession();
        FsInputs.Check(FsInputs.Zip(keys, tagSizes), messages, FsInputs.BitIndex(), (keyAndTag, message, bit) =>
        {
            var (keyValue, tagSize) = keyAndTag;
            WithSecretKey(backend, session, keyType, keyValue, b => b.Encrypt().Decrypt(), key =>
            {
                using TAead aead = create(key, tagSize);
                AeadEncrypt encrypt = encryptOf(aead);
                AeadDecrypt decrypt = decryptOf(aead);

                byte[] ciphertext = new byte[message.Plaintext.Length];
                byte[] tag = new byte[tagSize];
                encrypt(message.Nonce, message.Plaintext, ciphertext, tag, message.AssociatedData);

                byte[] opened = new byte[ciphertext.Length];
                decrypt(message.Nonce, ciphertext, tag, opened, message.AssociatedData);
                Assert.Equal(message.Plaintext, opened);

                // One bit of nonce || ciphertext || tag || aad, all of which the tag covers.
                byte[] sealedParts = [.. message.Nonce, .. ciphertext, .. tag, .. message.AssociatedData];
                byte[] tampered = FsInputs.FlipBit(sealedParts, bit);
                int c = message.Nonce.Length, t = c + ciphertext.Length, a = t + tagSize;
                byte[] destination = new byte[ciphertext.Length];
                destination.AsSpan().Fill(0xA5);

                Exception? ex = Record.Exception(() => decrypt(
                    tampered.AsSpan(0, c), tampered.AsSpan(c, ciphertext.Length), tampered.AsSpan(t, tagSize), destination, tampered.AsSpan(a)));

                switch (ex)
                {
                    case AuthenticationTagMismatchException:
                        Assert.All(destination, b => Assert.Equal(0, b));
                        break;
                    case Pkcs11Exception:
                        break;
                    default:
                        Assert.Fail(ex is null
                            ? "A message with one bit flipped decrypted without error."
                            : $"A message with one bit flipped failed with {ex.GetType().Name}, not a tag mismatch: {ex.Message}");
                        break;
                }
            });
        });
    }

    // === KDFs ==============================================================================
    //
    // The byte-returning overloads read the derived value back, which the default policy refuses; these
    // laws opt in for their session, as the differential properties do.

    // HKDF-Expand output is a stream: the first n bytes of a longer output are the n-byte output.
    internal static void Assert_Hkdf_ShorterOutputIsAPrefix(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        var hash = new HashAlgorithmName(hashName);
        int max = Math.Min(255 * Hash(hashName).Size, 512);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        FsInputs.Check(
            FsInputs.Zip(FsInputs.Bytes(1, 128), FsInputs.Bytes(0, 64), FsInputs.Bytes(0, 64)),
            FsInputs.Int(1, max), FsInputs.Int(1, max), (ikmSaltInfo, first, second) =>
            {
                var (ikmValue, salt, info) = ikmSaltInfo;
                WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, ikmValue, b => b.Derive(), ikm =>
                {
                    byte[] shorter = HkdfPkcs11.DeriveKey(hash, ikm, Math.Min(first, second), salt, info);
                    byte[] longer = HkdfPkcs11.DeriveKey(hash, ikm, Math.Max(first, second), salt, info);
                    Assert.Equal(shorter, longer.AsSpan(0, shorter.Length).ToArray());
                });
            });
    }

    // PBKDF2's output blocks do not depend on the output length, so a shorter output is a prefix of a
    // longer one. The iteration count stays near SP 800-132's floor of 1000, which FreeHSM enforces.
    internal static void Assert_Pbkdf2_ShorterOutputIsAPrefix(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        var hash = new HashAlgorithmName(hashName);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        FsInputs.Check(
            FsInputs.Zip(FsInputs.Bytes(0, 64), FsInputs.Bytes(16, 64), FsInputs.Int(1000, 1010)),
            FsInputs.Int(1, 160), FsInputs.Int(1, 160), (passwordSaltIterations, first, second) =>
            {
                var (password, salt, iterations) = passwordSaltIterations;
                byte[] shorter = Rfc2898DeriveBytesPkcs11.Pbkdf2(session, password.AsSpan(), salt, iterations, hash, Math.Min(first, second));
                byte[] longer = Rfc2898DeriveBytesPkcs11.Pbkdf2(session, password.AsSpan(), salt, iterations, hash, Math.Max(first, second));
                Assert.Equal(shorter, longer.AsSpan(0, shorter.Length).ToArray());
            });
    }

    // SP 800-108 binds the output length: [L] is part of every PRF input, so outputs of two different
    // lengths differ from the first byte on. A token that left [L] out would give a prefix instead. The
    // shorter output is at least 8 bytes, so two unrelated outputs agree on it by chance with odds of 2^-64.
    internal static void Assert_Sp800108HmacCounter_OutputLengthIsBound(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
        var hash = new HashAlgorithmName(hashName);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        FsInputs.Check(
            FsInputs.Zip(FsInputs.Bytes(16, 64), FsInputs.Bytes(0, 64), FsInputs.Bytes(0, 64)),
            FsInputs.Int(8, 255), FsInputs.Int(1, 64), (keyLabelContext, shorterLength, extra) =>
            {
                var (keyValue, label, context) = keyLabelContext;
                int longerLength = Math.Min(shorterLength + extra, 256);
                WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, keyValue, b => b.Derive().Sign(), key =>
                {
                    using var kdf = new SP800108HmacCounterKdfPkcs11(key, hash);
                    byte[] shorter = kdf.DeriveKey(label, context, shorterLength);
                    byte[] longer = kdf.DeriveKey(label, context, longerLength);
                    Assert.NotEqual(shorter, longer.AsSpan(0, shorter.Length).ToArray());
                });
            });
    }
}
