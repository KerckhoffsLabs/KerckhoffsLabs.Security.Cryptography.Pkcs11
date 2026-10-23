using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>Shared assertions for the CBC-PAD decryption of the block-cipher suites (AES, DES, 3DES).</summary>
internal static class CbcPaddingTestSupport
{
    /// <summary>
    /// Last plaintext blocks that carry no valid PKCS#7 padding, one per check an unpadder must make: a pad
    /// length of zero, a pad length past the block, and pad bytes that do not all equal the pad length.
    /// openCryptoki accepted all three until d5beecc9 and f14f7a91; the last is the one a check of the final
    /// byte alone lets through.
    /// </summary>
    internal static IEnumerable<(string Padding, byte[] Block)> BadlyPaddedBlocks(int blockSize)
    {
        yield return ("a pad length of 0", new byte[blockSize]);

        byte[] pastTheBlock = new byte[blockSize];
        pastTheBlock[^1] = (byte)(blockSize + 1);
        yield return ("a pad length past the block", pastTheBlock);

        byte[] mismatched = new byte[blockSize];
        mismatched.AsSpan().Fill(0x02);
        mismatched[^2] = 0x01;
        yield return ("pad bytes 01 02", mismatched);
    }

    /// <summary>
    /// Asserts that <paramref name="token"/> refuses every <see cref="BadlyPaddedBlocks"/> ciphertext, and one
    /// that is not a whole number of blocks, with a <see cref="CryptographicException"/> as
    /// <paramref name="bcl"/> does, and still decrypts afterwards. Both must hold the same key, and the caller
    /// must have run the mechanism once already, so that a token without it is skipped, not taken for one
    /// that refuses the padding.
    /// </summary>
    internal static void AssertRefusesBadPadding_SessionReusable(SymmetricAlgorithm token, SymmetricAlgorithm bcl, byte[] iv)
    {
        int blockSize = bcl.BlockSize / 8;
        Assert.All(BadlyPaddedBlocks(blockSize), bad =>
        {
            byte[] ciphertext = bcl.EncryptCbc(bad.Block, iv, PaddingMode.None);
            Assert.ThrowsAny<CryptographicException>(() => bcl.DecryptCbc(ciphertext, iv));
            Assert.ThrowsAny<CryptographicException>(() => token.DecryptCbc(ciphertext, iv));
        });
        Assert.ThrowsAny<CryptographicException>(() => token.DecryptCbc(new byte[blockSize - 1], iv));

        byte[] plaintext = Encoding.UTF8.GetBytes("after a padding error");
        Assert.Equal(plaintext, token.DecryptCbc(bcl.EncryptCbc(plaintext, iv), iv));
    }
}
