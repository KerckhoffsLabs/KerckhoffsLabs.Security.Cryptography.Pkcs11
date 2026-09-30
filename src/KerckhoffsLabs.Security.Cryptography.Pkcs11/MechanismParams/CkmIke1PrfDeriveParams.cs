using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_PRF_DERIVE_PARAMS"/>. Used with CKM_IKE1_PRF_DERIVE (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// Every key must come from the workspace that performs the derive; it is resolved to its object
/// handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmIke1PrfDeriveParams : MechanismParameters
{
    private readonly byte[] _ckyIBytes;
    private readonly byte[] _ckyRBytes;
    private readonly CKM _prfMechanism;
    private readonly Pkcs11Key _keygxy;
    private readonly Pkcs11Key? _prevKey;
    private readonly byte _keyNumber;

    /// <summary>
    /// Initializes IKEv1 PRF derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="keygxy">The shared-secret key g^xy.</param>
    /// <param name="prevKey">The previous-iteration key, or <c>null</c> when there is none.</param>
    /// <param name="ckyI">Initiator cookie (CKY_I).</param>
    /// <param name="ckyR">Responder cookie (CKY_R).</param>
    /// <param name="keyNumber">KEYMAT_INDEX byte.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="keygxy"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if a key has no secret-key object.</exception>
    public CkmIke1PrfDeriveParams(CKM prfMechanism, Pkcs11Key keygxy, Pkcs11Key? prevKey, ReadOnlySpan<byte> ckyI, ReadOnlySpan<byte> ckyR, byte keyNumber)
    {
        ArgumentNullException.ThrowIfNull(keygxy);
        keygxy.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(keygxy));
        prevKey?.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(prevKey));

        _ckyIBytes = ckyI.IsEmpty ? [] : ckyI.ToArray();
        _ckyRBytes = ckyR.IsEmpty ? [] : ckyR.ToArray();
        _prfMechanism = prfMechanism;
        _keygxy = keygxy;
        _prevKey = prevKey;
        _keyNumber = keyNumber;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_IKE1_PRF_DERIVE_PARAMS
        {
            PrfMechanism = CkULong.From((ulong)_prfMechanism, "prfMechanism"),
            HasPrevKey = _prevKey is not null,
            Keygxy = scope.KeyHandle(_keygxy, KeyHandlePart.Private, "keygxy"),
            PrevKey = _prevKey is null ? default : scope.KeyHandle(_prevKey, KeyHandlePart.Private, "prevKey"),
            CkyI = scope.Write(_ckyIBytes),
            CkyILen = (NativeCULong)_ckyIBytes.Length,
            CkyR = scope.Write(_ckyRBytes),
            CkyRLen = (NativeCULong)_ckyRBytes.Length,
            KeyNumber = _keyNumber,
        };
    }
}
