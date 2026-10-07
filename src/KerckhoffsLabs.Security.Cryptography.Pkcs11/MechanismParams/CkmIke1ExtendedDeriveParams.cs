using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE1_EXTENDED_DERIVE_PARAMS"/>. Used with CKM_IKE1_EXTENDED_DERIVE (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// A <c>keygxy</c> key must come from the workspace that performs the derive; it is resolved to its
/// object handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmIke1ExtendedDeriveParams : MechanismParameters
{
    private readonly byte[] _extraDataBytes;
    private readonly CKM _prfMechanism;
    private readonly Pkcs11Key? _keygxy;

    /// <summary>
    /// Initializes IKEv1 extended-derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="keygxy">The shared-secret key g^xy, or <c>null</c> when there is none.</param>
    /// <param name="extraData">Additional input data.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="keygxy"/> has no secret-key object.</exception>
    public CkmIke1ExtendedDeriveParams(CKM prfMechanism, Pkcs11Key? keygxy, ReadOnlySpan<byte> extraData)
    {
        keygxy?.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(keygxy));

        _extraDataBytes = extraData.ToArray();
        _prfMechanism = prfMechanism;
        _keygxy = keygxy;
    }

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_IKE1_EXTENDED_DERIVE_PARAMS
        {
            PrfMechanism = CkULong.From((ulong)_prfMechanism, "prfMechanism"),
            HasKeygxy = CkBbool.From(_keygxy is not null),
            Keygxy = _keygxy is null ? default : scope.KeyHandle(_keygxy, KeyHandlePart.Private, "keygxy"),
            ExtraData = scope.Write(_extraDataBytes),
            ExtraDataLen = (NativeCULong)_extraDataBytes.Length,
        });
    }
}
