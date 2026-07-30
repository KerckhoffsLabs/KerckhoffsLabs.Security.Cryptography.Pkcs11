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
    private bool _disposed;

    /// <summary>
    /// Initializes ChaCha20 raw-mode parameters.
    /// </summary>
    /// <param name="blockCounter">Initial block-counter bytes (little-endian, typically 4 bytes for IETF mode).</param>
    /// <param name="blockCounterBits">Counter width in bits (32 for IETF, 64 for legacy).</param>
    /// <param name="nonce">Nonce bytes (12 for IETF, 8 for legacy).</param>
    /// <param name="nonceBits">Nonce length in bits.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="blockCounter"/> or <paramref name="nonce"/> is empty.</exception>
    public CkmChaCha20Params(ReadOnlySpan<byte> blockCounter, int blockCounterBits, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.IsEmpty) throw new ArgumentException("Block counter must not be empty.", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _blockCounterBytes = blockCounter.ToArray();
        _nonceBytes = nonce.ToArray();
        _blockCounterBits = blockCounterBits;
        _nonceBits = nonceBits;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_CHACHA20_PARAMS
        {
            BlockCounter = scope.Write(_blockCounterBytes),
            BlockCounterBits = (NativeCULong)_blockCounterBits,
            Nonce = scope.Write(_nonceBytes),
            NonceBits = (NativeCULong)_nonceBits,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
