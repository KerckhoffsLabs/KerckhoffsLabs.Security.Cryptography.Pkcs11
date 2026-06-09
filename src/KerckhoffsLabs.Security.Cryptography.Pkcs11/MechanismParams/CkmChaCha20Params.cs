using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CHACHA20_PARAMS"/>. Used with the raw CKM_CHACHA20 stream cipher mechanism (PKCS#11 v3.0).
/// </summary>
public sealed class CkmChaCha20Params : MechanismParameters
{
    private CK_CHACHA20_PARAMS _lowLevelParams;
    private IntPtr _blockCounter;
    private IntPtr _nonce;
    private bool _disposed;

    /// <summary>
    /// Initializes ChaCha20 raw-mode parameters.
    /// </summary>
    /// <param name="blockCounter">Initial block-counter bytes (little-endian, typically 4 bytes for IETF mode).</param>
    /// <param name="blockCounterBits">Counter width in bits (32 for IETF, 64 for legacy).</param>
    /// <param name="nonce">Nonce bytes (12 for IETF, 8 for legacy).</param>
    /// <param name="nonceBits">Nonce length in bits.</param>
    public CkmChaCha20Params(ReadOnlySpan<byte> blockCounter, int blockCounterBits, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.IsEmpty) throw new ArgumentException("Block counter must not be empty.", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _blockCounter = UnmanagedMemory.Allocate(blockCounter.Length);
        UnmanagedMemory.Write(_blockCounter, blockCounter);
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _lowLevelParams = new()
        {
            BlockCounter = _blockCounter,
            BlockCounterBits = (NativeCULong)blockCounterBits,
            Nonce = _nonce,
            NonceBits = (NativeCULong)nonceBits,
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _blockCounter);
        UnmanagedMemory.Free(ref _nonce);
        _lowLevelParams.BlockCounter = IntPtr.Zero;
        _lowLevelParams.Nonce = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmChaCha20Params() => Dispose(false);
}
