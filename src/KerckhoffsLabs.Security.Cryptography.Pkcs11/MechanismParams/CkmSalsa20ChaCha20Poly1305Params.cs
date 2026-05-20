using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SALSA20_CHACHA20_POLY1305_PARAMS"/>. Owns
/// the unmanaged buffers for the nonce and AAD. Dispose this instance AFTER the
/// <see cref="Mechanism"/> that holds a reference to it has been disposed.
/// </summary>
public sealed class CkmSalsa20ChaCha20Poly1305Params : IMechanismParams
{
    private CK_SALSA20_CHACHA20_POLY1305_PARAMS _lowLevelParams;
    private IntPtr _nonce;
    private IntPtr _aad;
    private bool _disposed;

    /// <summary>
    /// Initializes the ChaCha20-Poly1305 / Salsa20-Poly1305 parameters.
    /// </summary>
    /// <param name="nonce">Nonce (typically 12 bytes / 96 bits for ChaCha20-Poly1305).</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    public CkmSalsa20ChaCha20Poly1305Params(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad)
    {
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        if (!aad.IsEmpty)
        {
            _aad = UnmanagedMemory.Allocate(aad.Length);
            UnmanagedMemory.Write(_aad, aad);
        }

        _lowLevelParams = new()
        {
            Nonce = _nonce,
            NonceLen = (NativeCULong)nonce.Length,
            AAD = _aad,
            AADLen = (NativeCULong)aad.Length,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _nonce);
        UnmanagedMemory.Free(ref _aad);
        _lowLevelParams.Nonce = IntPtr.Zero;
        _lowLevelParams.AAD = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSalsa20ChaCha20Poly1305Params() => Dispose();
}
