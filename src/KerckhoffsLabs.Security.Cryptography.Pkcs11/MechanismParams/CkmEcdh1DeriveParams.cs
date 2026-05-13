using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_ECDH1_DERIVE_PARAMS"/>. Owns the unmanaged
/// buffers for the peer's public point and the optional shared data.
/// Dispose this instance AFTER the <see cref="Mechanism"/> that holds a reference
/// to it has been disposed.
/// </summary>
public sealed class CkmEcdh1DeriveParams : IMechanismParams
{
    private CK_ECDH1_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _publicData;
    private IntPtr _sharedData;
    private bool _disposed;

    /// <summary>
    /// Initializes ECDH1-derive parameters.
    /// </summary>
    /// <param name="kdf">Key derivation function (typically <see cref="CKD.CKD_SHA256_KDF"/> or stronger). Use <see cref="CKD.CKD_NULL"/> only if the caller will derive separately.</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value).</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    public CkmEcdh1DeriveParams(CKD kdf, ReadOnlySpan<byte> peerPublicPoint, ReadOnlySpan<byte> sharedData = default)
    {
        if (peerPublicPoint.IsEmpty)
            throw new ArgumentException("Peer public point must not be empty.", nameof(peerPublicPoint));

        _publicData = UnmanagedMemory.Allocate(peerPublicPoint.Length);
        UnmanagedMemory.Write(_publicData, peerPublicPoint);

        if (!sharedData.IsEmpty)
        {
            _sharedData = UnmanagedMemory.Allocate(sharedData.Length);
            UnmanagedMemory.Write(_sharedData, sharedData);
        }

        _lowLevelParams = new CK_ECDH1_DERIVE_PARAMS
        {
            Kdf = kdf.ToCULong(),
            SharedData = _sharedData,
            SharedDataLen = (NativeCULong)sharedData.Length,
            PublicData = _publicData,
            PublicDataLen = (NativeCULong)peerPublicPoint.Length,
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
        UnmanagedMemory.Free(ref _publicData);
        UnmanagedMemory.Free(ref _sharedData);
        _lowLevelParams.PublicData = IntPtr.Zero;
        _lowLevelParams.SharedData = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmEcdh1DeriveParams() => Dispose();
}
