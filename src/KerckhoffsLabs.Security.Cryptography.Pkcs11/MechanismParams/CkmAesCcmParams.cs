using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CCM_PARAMS"/>. Owns the unmanaged buffers for
/// the nonce and AAD. Dispose AFTER the Mechanism holding it has been disposed.
/// </summary>
public sealed class CkmAesCcmParams : IMechanismParams
{
    private CK_CCM_PARAMS _lowLevelParams;
    private IntPtr _nonce;
    private IntPtr _aad;
    private bool _disposed;

    /// <summary>
    /// Initializes the CCM parameters.
    /// </summary>
    /// <param name="dataLen">Length of the plaintext (CCM requires it known up-front).</param>
    /// <param name="nonce">Nonce (BCL: 7-13 bytes). Must not be empty.</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="macLen">MAC (tag) length in bytes; must be one of {4, 6, 8, 10, 12, 14, 16}.</param>
    public CkmAesCcmParams(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, int macLen)
    {
        if (dataLen < 0) throw new ArgumentOutOfRangeException(nameof(dataLen));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));
        if (macLen is not (4 or 6 or 8 or 10 or 12 or 14 or 16))
            throw new ArgumentOutOfRangeException(nameof(macLen),
                "CCM MAC length must be one of {4, 6, 8, 10, 12, 14, 16} bytes.");

        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        if (!aad.IsEmpty)
        {
            _aad = UnmanagedMemory.Allocate(aad.Length);
            UnmanagedMemory.Write(_aad, aad);
        }

        _lowLevelParams = new CK_CCM_PARAMS
        {
            DataLen = (NativeCULong)dataLen,
            Nonce = _nonce,
            NonceLen = (NativeCULong)nonce.Length,
            AAD = _aad,
            AADLen = (NativeCULong)aad.Length,
            MACLen = (NativeCULong)macLen,
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
    ~CkmAesCcmParams() => Dispose();
}
