using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_PRF_DERIVE_PARAMS"/>. Used with CKM_IKE1_PRF_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke1PrfDeriveParams : MechanismParameters
{
    private CK_IKE1_PRF_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _ckyI;
    private IntPtr _ckyR;
    private bool _disposed;

    /// <summary>
    /// Initializes IKEv1 PRF derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="hasPrevKey">True if <paramref name="prevKey"/> is valid.</param>
    /// <param name="keygxy">Handle of the shared-secret key g^xy.</param>
    /// <param name="prevKey">Handle of the previous-iteration key (when <paramref name="hasPrevKey"/> is true).</param>
    /// <param name="ckyI">Initiator cookie (CKY_I).</param>
    /// <param name="ckyR">Responder cookie (CKY_R).</param>
    /// <param name="keyNumber">KEYMAT_INDEX byte.</param>
    public CkmIke1PrfDeriveParams(CKM prfMechanism, bool hasPrevKey, ulong keygxy, ulong prevKey, ReadOnlySpan<byte> ckyI, ReadOnlySpan<byte> ckyR, byte keyNumber)
    {
        if (!ckyI.IsEmpty)
        {
            _ckyI = UnmanagedMemory.Allocate(ckyI.Length);
            UnmanagedMemory.Write(_ckyI, ckyI);
        }

        if (!ckyR.IsEmpty)
        {
            _ckyR = UnmanagedMemory.Allocate(ckyR.Length);
            UnmanagedMemory.Write(_ckyR, ckyR);
        }

        _lowLevelParams = new()
        {
            PrfMechanism = (NativeCULong)(ulong)prfMechanism,
            HasPrevKey = hasPrevKey,
            Keygxy = (NativeCULong)keygxy,
            PrevKey = (NativeCULong)prevKey,
            CkyI = _ckyI,
            CkyILen = (NativeCULong)ckyI.Length,
            CkyR = _ckyR,
            CkyRLen = (NativeCULong)ckyR.Length,
            KeyNumber = keyNumber,
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
        UnmanagedMemory.Free(ref _ckyI);
        UnmanagedMemory.Free(ref _ckyR);
        _lowLevelParams.CkyI = IntPtr.Zero;
        _lowLevelParams.CkyR = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmIke1PrfDeriveParams() => Dispose();
}
