using System.Security.Cryptography;
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

    /// <summary>The key derivation function applied to the shared secret, as the crypto policy sees it.</summary>
    internal CKD Kdf => _kdf;

    /// <summary>The peer's public point as passed to the token; empty for <see cref="ForEncapsulation"/>.</summary>
    internal ReadOnlySpan<byte> PublicData => _publicDataBytes;

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

    /// <summary>
    /// Builds ECDH1-derive parameters for <c>C_DeriveKey</c> from the peer's public key as the BCL
    /// represents it, encoding its point the way PKCS#11 expects (a DER OCTET STRING wrapping the
    /// uncompressed point <c>04 ‖ X ‖ Y</c>).
    /// </summary>
    /// <remarks>
    /// Only the point is encoded; the curve is not carried by the mechanism. The operations that take
    /// these parameters and know the local key —
    /// <see cref="Pkcs11Workspace.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/> and
    /// <see cref="Pkcs11Key.DeriveAndExportSecret"/> — check the point against the local key's curve
    /// before it reaches the token.
    /// </remarks>
    /// <param name="kdf">Key derivation function applied to the shared secret.</param>
    /// <param name="peerPublicKey">The peer's public key. Both coordinates of <see cref="ECParameters.Q"/> are required and must have the same length.</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    /// <returns>Parameters carrying the encoded peer point.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicKey"/> has no X or Y coordinate, or the two differ in length.</exception>
    public static CkmEcdh1DeriveParams ForPeer(CKD kdf, ECParameters peerPublicKey, ReadOnlySpan<byte> sharedData = default)
    {
        byte[] x = peerPublicKey.Q.X ?? throw new ArgumentException("Peer public key has no X coordinate.", nameof(peerPublicKey));
        byte[] y = peerPublicKey.Q.Y ?? throw new ArgumentException("Peer public key has no Y coordinate.", nameof(peerPublicKey));
        if (x.Length == 0 || x.Length != y.Length)
            throw new ArgumentException(
                $"Peer public key coordinates must be non-empty and of equal length; got {x.Length} and {y.Length} bytes.",
                nameof(peerPublicKey));
        return new(kdf, EncodeUncompressedPoint(x, y), sharedData.IsEmpty ? [] : sharedData.ToArray(), default);
    }

    /// <summary>
    /// Encodes an uncompressed EC point (<c>04 ‖ X ‖ Y</c>) as a DER OCTET STRING — the full
    /// <c>CKA_EC_POINT</c> form, which PKCS#11 accepts for the ECDH1 public-data parameter.
    /// </summary>
    internal static byte[] EncodeUncompressedPoint(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        int pointLength = 1 + x.Length + y.Length;
        // Short-form length below 128 bytes; one long-form length byte covers every named curve
        // (the largest, P-521, has a 133-byte point).
        int header = pointLength < 0x80 ? 2 : 3;
        byte[] der = new byte[header + pointLength];
        der[0] = 0x04;
        if (header == 2)
        {
            der[1] = (byte)pointLength;
        }
        else
        {
            der[1] = 0x81;
            der[2] = checked((byte)pointLength);
        }
        der[header] = 0x04;
        x.CopyTo(der.AsSpan(header + 1));
        y.CopyTo(der.AsSpan(header + 1 + x.Length));
        return der;
    }

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
            Kdf = CkULong.From((ulong)_kdf, "kdf"),
            SharedData = scope.Write(_sharedDataBytes),
            SharedDataLen = (NativeCULong)_sharedDataBytes.Length,
            PublicData = scope.Write(_publicDataBytes),
            PublicDataLen = (NativeCULong)_publicDataBytes.Length,
        };
    }
}
