using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_PRF_DERIVE_PARAMS"/>. Used with CKM_IKE1_PRF_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke1PrfDeriveParams : MechanismParameters
{
    private readonly byte[] _ckyIBytes;
    private readonly byte[] _ckyRBytes;
    private readonly CKM _prfMechanism;
    private readonly bool _hasPrevKey;
    private readonly ulong _keygxy;
    private readonly ulong _prevKey;
    private readonly byte _keyNumber;
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
        _ckyIBytes = ckyI.IsEmpty ? [] : ckyI.ToArray();
        _ckyRBytes = ckyR.IsEmpty ? [] : ckyR.ToArray();
        _prfMechanism = prfMechanism;
        _hasPrevKey = hasPrevKey;
        _keygxy = keygxy;
        _prevKey = prevKey;
        _keyNumber = keyNumber;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_IKE1_PRF_DERIVE_PARAMS
        {
            PrfMechanism = (NativeCULong)(ulong)_prfMechanism,
            HasPrevKey = _hasPrevKey,
            Keygxy = (NativeCULong)_keygxy,
            PrevKey = (NativeCULong)_prevKey,
            CkyI = scope.Write(_ckyIBytes),
            CkyILen = (NativeCULong)_ckyIBytes.Length,
            CkyR = scope.Write(_ckyRBytes),
            CkyRLen = (NativeCULong)_ckyRBytes.Length,
            KeyNumber = _keyNumber,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
