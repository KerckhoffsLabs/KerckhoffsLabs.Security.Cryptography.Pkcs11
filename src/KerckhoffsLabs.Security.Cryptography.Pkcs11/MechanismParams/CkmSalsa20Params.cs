using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SALSA20_PARAMS"/>. Used with the raw CKM_SALSA20 stream cipher mechanism (PKCS#11 v3.0).
/// </summary>
public sealed class CkmSalsa20Params : MechanismParameters
{
    private CK_SALSA20_PARAMS _lowLevelParams;
    private IntPtr _blockCounter;
    private IntPtr _nonce;
    private readonly byte[] _blockCounterBytes;
    private readonly byte[] _nonceBytes;
    private readonly int _nonceBits;
    private bool _disposed;

    /// <summary>
    /// Initializes Salsa20 raw-mode parameters.
    /// </summary>
    /// <param name="blockCounter">Initial block counter (8 bytes).</param>
    /// <param name="nonce">Nonce bytes (typically 8).</param>
    /// <param name="nonceBits">Nonce length in bits (typically 64).</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="blockCounter"/> or <paramref name="nonce"/> is empty.</exception>
    public CkmSalsa20Params(ReadOnlySpan<byte> blockCounter, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.IsEmpty) throw new ArgumentException("Block counter must not be empty.", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _blockCounter = UnmanagedMemory.Allocate(blockCounter.Length);
        UnmanagedMemory.Write(_blockCounter, blockCounter);
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _blockCounterBytes = blockCounter.ToArray();
        _nonceBytes = nonce.ToArray();
        _nonceBits = nonceBits;

        _lowLevelParams = new()
        {
            BlockCounter = _blockCounter,
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
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_SALSA20_PARAMS
        {
            BlockCounter = scope.Write(_blockCounterBytes),
            Nonce = scope.Write(_nonceBytes),
            NonceBits = (NativeCULong)_nonceBits,
        };
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
    ~CkmSalsa20Params() => Dispose(false);
}
