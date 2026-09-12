using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_ECDH1_DERIVE_PARAMS"/>. A managed descriptor: it holds the
/// peer's public point (or none, for <see cref="ForEncapsulation"/>) and the optional shared data as
/// managed arrays and is rebuilt into each call's own scope, so one instance may safely back several
/// mechanisms.
/// </summary>
public sealed class CkmEcdh1DeriveParams : MechanismParameters
{
    private readonly byte[] _publicDataBytes;
    private readonly byte[] _sharedDataBytes;
    private readonly CKD _kdf;

    /// <summary>
    /// Initializes ECDH1-derive parameters for <c>C_DeriveKey</c>.
    /// </summary>
    /// <param name="kdf">Key derivation function (typically <see cref="CKD.CKD_SHA256_KDF"/> or stronger). Use <see cref="CKD.CKD_NULL"/> only if the caller will derive separately.</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value).</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicPoint"/> is empty.</exception>
    public CkmEcdh1DeriveParams(CKD kdf, ReadOnlySpan<byte> peerPublicPoint, ReadOnlySpan<byte> sharedData = default)
        : this(kdf, RequireNonEmptyPeerPoint(peerPublicPoint), sharedData.IsEmpty ? [] : sharedData.ToArray(), default(RawParams))
    {
    }

    /// <summary>
    /// Builds <c>CK_ECDH1_DERIVE_PARAMS</c> for use with <see cref="Pkcs11Key.EncapsulateKey"/> /
    /// <see cref="Pkcs11Key.DecapsulateKey"/> (PKCS#11 v3.2 §5.18.10/.11) rather than
    /// <c>C_DeriveKey</c>. For that call shape the spec requires <c>pPublicData</c> to be empty: the
    /// token generates its own ephemeral EC key pair internally, computes the shared secret against
    /// the public/private key passed to Encapsulate/DecapsulateKey, and returns the ephemeral public
    /// point as the KEM ciphertext. Passing a peer public point here would be a spec violation for
    /// this call shape, so unlike the general constructor, this factory takes none.
    /// </summary>
    /// <param name="kdf">Key derivation function (typically <see cref="CKD.CKD_SHA256_KDF"/> or stronger). Use <see cref="CKD.CKD_NULL"/> only if the caller will derive separately.</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    public static CkmEcdh1DeriveParams ForEncapsulation(CKD kdf, ReadOnlySpan<byte> sharedData = default) =>
        new(kdf, [], sharedData.IsEmpty ? [] : sharedData.ToArray(), default);

    // Unambiguous overload marker: byte[] converts implicitly to ReadOnlySpan<byte>, so without this
    // extra parameter the compiler cannot tell this constructor apart from the validating public one.
    private readonly struct RawParams;

    private CkmEcdh1DeriveParams(CKD kdf, byte[] publicDataBytes, byte[] sharedDataBytes, RawParams _)
    {
        _kdf = kdf;
        _publicDataBytes = publicDataBytes;
        _sharedDataBytes = sharedDataBytes;
    }

    private static byte[] RequireNonEmptyPeerPoint(ReadOnlySpan<byte> peerPublicPoint)
    {
        if (peerPublicPoint.IsEmpty)
            throw new ArgumentException("Peer public point must not be empty.", nameof(peerPublicPoint));
        return peerPublicPoint.ToArray();
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
