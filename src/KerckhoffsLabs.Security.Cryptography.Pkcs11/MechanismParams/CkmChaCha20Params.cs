using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CHACHA20_PARAMS"/>. Used with the raw CKM_CHACHA20 stream cipher mechanism (PKCS#11 v3.0).
/// </summary>
public sealed class CkmChaCha20Params : MechanismParameters
{
    private readonly byte[] _blockCounterBytes;
    private readonly byte[] _nonceBytes;
    private readonly int _blockCounterBits;
    private readonly int _nonceBits;

    /// <summary>
    /// Initializes ChaCha20 raw-mode parameters.
    /// </summary>
    /// <param name="blockCounter">Initial block-counter bytes (little-endian, typically 4 bytes for IETF mode).</param>
    /// <param name="blockCounterBits">Counter width in bits (32 for IETF, 64 for legacy).</param>
    /// <param name="nonce">Nonce bytes (12 for IETF, 8 for legacy).</param>
    /// <param name="nonceBits">Nonce length in bits (96 for IETF, 64 for legacy).</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="blockCounter"/> or <paramref name="nonce"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if <paramref name="blockCounterBits"/> is not 32 or 64, if <paramref name="nonceBits"/> is not
    /// 64 or 96, or if either bit width exceeds the byte length of its buffer — the module reads
    /// <c>bits / 8</c> bytes from the pointer regardless of the buffer's actual size, so an oversized value
    /// here is an out-of-bounds read on the token.
    /// </exception>
    public CkmChaCha20Params(ReadOnlySpan<byte> blockCounter, int blockCounterBits, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.IsEmpty) throw new ArgumentException("Block counter must not be empty.", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));
        if (blockCounterBits is not 32 and not 64)
            throw new ArgumentOutOfRangeException(nameof(blockCounterBits), blockCounterBits,
                "CKM_CHACHA20 defines the block counter width as 32 (IETF) or 64 (legacy) bits.");
        if (blockCounterBits / 8 > blockCounter.Length)
            throw new ArgumentOutOfRangeException(nameof(blockCounterBits), blockCounterBits,
                $"Exceeds the block counter buffer's length ({blockCounter.Length} bytes).");
        if (nonceBits is not 64 and not 96)
            throw new ArgumentOutOfRangeException(nameof(nonceBits), nonceBits,
                "CKM_CHACHA20 defines the nonce width as 64 (legacy) or 96 (IETF) bits.");
        if (nonceBits / 8 > nonce.Length)
            throw new ArgumentOutOfRangeException(nameof(nonceBits), nonceBits,
                $"Exceeds the nonce buffer's length ({nonce.Length} bytes).");

        _blockCounterBytes = blockCounter.ToArray();
        _nonceBytes = nonce.ToArray();
        _blockCounterBits = blockCounterBits;
        _nonceBits = nonceBits;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_CHACHA20_PARAMS
        {
            BlockCounter = scope.Write(_blockCounterBytes),
            BlockCounterBits = (NativeCULong)_blockCounterBits,
            Nonce = scope.Write(_nonceBytes),
            NonceBits = (NativeCULong)_nonceBits,
        };
    }
}
