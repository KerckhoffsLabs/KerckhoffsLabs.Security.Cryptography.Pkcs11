using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_EXTENDED_DERIVE_PARAMS"/>. Used with CKM_IKE1_EXTENDED_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke1ExtendedDeriveParams : MechanismParameters
{
    private readonly byte[] _extraDataBytes;
    private readonly CKM _prfMechanism;
    private readonly bool _hasKeygxy;
    private readonly ulong _keygxy;
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
        _extraDataBytes = extraData.ToArray();
        _prfMechanism = prfMechanism;
        _hasKeygxy = hasKeygxy;
        _keygxy = keygxy;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_IKE1_EXTENDED_DERIVE_PARAMS
        {
            PrfMechanism = _prfMechanism.ToCULong(),
            HasKeygxy = _hasKeygxy,
            Keygxy = (NativeCULong)_keygxy,
            ExtraData = scope.Write(_extraDataBytes),
            ExtraDataLen = (NativeCULong)_extraDataBytes.Length,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
