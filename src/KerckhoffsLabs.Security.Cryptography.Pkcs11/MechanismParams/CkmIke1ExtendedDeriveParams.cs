using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_EXTENDED_DERIVE_PARAMS"/>. Used with CKM_IKE1_EXTENDED_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke1ExtendedDeriveParams : MechanismParameters
{
    private CK_IKE1_EXTENDED_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _extraData;
    private bool _disposed;

    /// <summary>
    /// Initializes IKEv1 extended-derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="hasKeygxy">True if <paramref name="keygxy"/> is valid.</param>
    /// <param name="keygxy">Handle of the shared-secret key g^xy.</param>
    /// <param name="extraData">Additional input data.</param>
    public CkmIke1ExtendedDeriveParams(CKM prfMechanism, bool hasKeygxy, ulong keygxy, ReadOnlySpan<byte> extraData)
    {
        if (!extraData.IsEmpty)
        {
            _extraData = UnmanagedMemory.Allocate(extraData.Length);
            UnmanagedMemory.Write(_extraData, extraData);
        }

        _lowLevelParams = new()
        {
            PrfMechanism = (NativeCULong)(ulong)prfMechanism,
            HasKeygxy = hasKeygxy,
            Keygxy = (NativeCULong)keygxy,
            ExtraData = _extraData,
            ExtraDataLen = (NativeCULong)extraData.Length,
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _extraData);
        _lowLevelParams.ExtraData = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmIke1ExtendedDeriveParams() => Dispose();
}
