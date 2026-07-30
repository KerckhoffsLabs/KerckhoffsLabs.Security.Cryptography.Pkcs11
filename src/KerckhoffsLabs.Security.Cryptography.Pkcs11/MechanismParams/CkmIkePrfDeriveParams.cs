using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE_PRF_DERIVE_PARAMS"/>. Used with CKM_IKE_PRF_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIkePrfDeriveParams : MechanismParameters
{
    private readonly byte[] _niBytes;
    private readonly byte[] _nrBytes;
    private readonly CKM _prfMechanism;
    private readonly bool _dataAsKey;
    private readonly bool _rekey;
    private readonly ulong _newKey;

    /// <summary>
    /// Initializes IKE PRF derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="dataAsKey">True to treat the input data as the key material.</param>
    /// <param name="rekey">True to perform a rekey-style derivation.</param>
    /// <param name="ni">Initiator nonce (Ni).</param>
    /// <param name="nr">Responder nonce (Nr).</param>
    /// <param name="newKey">New-key handle used in some rekey flows.</param>
    public CkmIkePrfDeriveParams(CKM prfMechanism, bool dataAsKey, bool rekey, ReadOnlySpan<byte> ni, ReadOnlySpan<byte> nr, ulong newKey)
    {
        _niBytes = ni.IsEmpty ? [] : ni.ToArray();
        _nrBytes = nr.IsEmpty ? [] : nr.ToArray();
        _prfMechanism = prfMechanism;
        _dataAsKey = dataAsKey;
        _rekey = rekey;
        _newKey = newKey;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_IKE_PRF_DERIVE_PARAMS
        {
            PrfMechanism = (NativeCULong)(ulong)_prfMechanism,
            DataAsKey = _dataAsKey,
            Rekey = _rekey,
            Ni = scope.Write(_niBytes),
            NiLen = (NativeCULong)_niBytes.Length,
            Nr = scope.Write(_nrBytes),
            NrLen = (NativeCULong)_nrBytes.Length,
            NewKey = (NativeCULong)_newKey,
        };
    }
}
