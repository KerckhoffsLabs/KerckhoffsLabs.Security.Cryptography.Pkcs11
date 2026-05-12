using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_GCM_PARAMS"/>. Owns the unmanaged buffers
/// for the IV and AAD. Dispose this instance AFTER the <see cref="Mechanism"/> that
/// holds a reference to it has been disposed.
/// </summary>
public sealed class CkmAesGcmParams : IMechanismParams
{
    private CK_GCM_PARAMS _lowLevelParams;
    private IntPtr _iv;
    private IntPtr _aad;
    private bool _disposed;

    /// <summary>
    /// Initializes the GCM parameters.
    /// </summary>
    /// <param name="iv">Initialization vector (typically 12 bytes / 96 bits).</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="tagBits">Authentication tag length in bits; must be a multiple of 8 in [32, 128]. Use 128 unless you have a specific reason.</param>
    public CkmAesGcmParams(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, int tagBits)
    {
        if (iv.IsEmpty) throw new ArgumentException("IV must not be empty.", nameof(iv));
        if (tagBits < 32 || tagBits > 128 || (tagBits % 8) != 0)
            throw new ArgumentOutOfRangeException(nameof(tagBits), "Tag size must be a multiple of 8 in [32, 128] bits.");

        _iv = UnmanagedMemory.Allocate(iv.Length);
        UnmanagedMemory.Write(_iv, iv);

        if (!aad.IsEmpty)
        {
            _aad = UnmanagedMemory.Allocate(aad.Length);
            UnmanagedMemory.Write(_aad, aad);
        }

        _lowLevelParams = new CK_GCM_PARAMS
        {
            Iv = _iv,
            IvLen = (NativeCULong)iv.Length,
            IvBits = (NativeCULong)(iv.Length * 8),
            AAD = _aad,
            AADLen = (NativeCULong)aad.Length,
            TagBits = (NativeCULong)tagBits,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        if (_disposed) throw new ObjectDisposedException(GetType().FullName);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _iv);
        UnmanagedMemory.Free(ref _aad);
        _lowLevelParams.Iv = IntPtr.Zero;
        _lowLevelParams.AAD = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmAesGcmParams() => Dispose();
}
