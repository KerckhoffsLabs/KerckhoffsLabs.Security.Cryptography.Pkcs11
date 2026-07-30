using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_ECDH1_DERIVE_PARAMS"/>. A managed descriptor: it holds the
/// peer's public point and the optional shared data as managed arrays and is rebuilt into each
/// call's own scope, so one instance may safely back several mechanisms.
/// </summary>
public sealed class CkmEcdh1DeriveParams : MechanismParameters
{
    private readonly byte[] _publicDataBytes;
    private readonly byte[] _sharedDataBytes;
    private readonly CKD _kdf;

    /// <summary>
    /// Initializes ECDH1-derive parameters.
    /// </summary>
    /// <param name="kdf">Key derivation function (typically <see cref="CKD.CKD_SHA256_KDF"/> or stronger). Use <see cref="CKD.CKD_NULL"/> only if the caller will derive separately.</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value).</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicPoint"/> is empty.</exception>
    public CkmEcdh1DeriveParams(CKD kdf, ReadOnlySpan<byte> peerPublicPoint, ReadOnlySpan<byte> sharedData = default)
    {
        if (peerPublicPoint.IsEmpty)
            throw new ArgumentException("Peer public point must not be empty.", nameof(peerPublicPoint));

        _publicDataBytes = peerPublicPoint.ToArray();
        _sharedDataBytes = sharedData.IsEmpty ? [] : sharedData.ToArray();
        _kdf = kdf;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_ECDH1_DERIVE_PARAMS
        {
            Kdf = _kdf.ToCULong(),
            SharedData = scope.Write(_sharedDataBytes),
            SharedDataLen = (NativeCULong)_sharedDataBytes.Length,
            PublicData = scope.Write(_publicDataBytes),
            PublicDataLen = (NativeCULong)_publicDataBytes.Length,
        };
    }
}
