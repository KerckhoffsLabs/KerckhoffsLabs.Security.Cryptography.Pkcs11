using System.Buffers.Binary;
using System.Numerics;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2), test-side. XChaCha20 under a key and a 192-bit nonce is ChaCha20 with a
/// 64-bit block counter and a 64-bit nonce under the subkey HChaCha20(key, nonce[0..16]), with the nonce's last eight
/// bytes as its nonce. PKCS#11 has no XChaCha20, but <c>CKM_CHACHA20</c> with a 64-bit counter is that second step, so
/// this derives the subkey for the Wycheproof XChaCha20 counter vectors.
/// </summary>
internal static class HChaCha20
{
    public static byte[] DeriveSubkey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce16)
    {
        if (key.Length != 32) throw new ArgumentException("HChaCha20 takes a 32-byte key.", nameof(key));
        if (nonce16.Length != 16) throw new ArgumentException("HChaCha20 takes a 16-byte nonce.", nameof(nonce16));

        Span<uint> s = stackalloc uint[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        for (int i = 0; i < 4; i++) s[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[(4 * i)..]);

        for (int round = 0; round < 10; round++)
        {
            QuarterRound(s, 0, 4, 8, 12); QuarterRound(s, 1, 5, 9, 13); QuarterRound(s, 2, 6, 10, 14); QuarterRound(s, 3, 7, 11, 15);
            QuarterRound(s, 0, 5, 10, 15); QuarterRound(s, 1, 6, 11, 12); QuarterRound(s, 2, 7, 8, 13); QuarterRound(s, 3, 4, 9, 14);
        }

        // Unlike the ChaCha20 block function, no feed-forward: the subkey is words 0-3 and 12-15 of the permuted state.
        byte[] subkey = new byte[32];
        for (int i = 0; i < 4; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(4 * i), s[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(16 + 4 * i), s[12 + i]);
        }
        return subkey;
    }

    // The test project checks arithmetic; ChaCha20's additions are mod 2^32.
    private static void QuarterRound(Span<uint> s, int a, int b, int c, int d)
    {
        unchecked
        {
            s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 16);
            s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 12);
            s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 8);
            s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 7);
        }
    }
}
