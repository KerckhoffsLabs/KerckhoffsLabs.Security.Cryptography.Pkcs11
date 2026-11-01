using System.Formats.Asn1;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// A peer's X25519 or X448 public key that passed <see cref="MontgomeryPeerValidator.Validate"/>.
/// </summary>
/// <param name="U">The peer's u-coordinate as RFC 7748 encodes it (little-endian), the <c>CKM_ECDH1_DERIVE</c> public data for a <see cref="CKK.CKK_EC_MONTGOMERY"/> key.</param>
/// <param name="SecretLength">The length of the curve's shared secret, and of <see cref="U"/>: 32 bytes for X25519, 56 for X448.</param>
internal readonly record struct ValidatedMontgomeryPeer(byte[] U, int SecretLength);

/// <summary>A Montgomery curve this library can agree on: X25519 or X448.</summary>
/// <param name="Oid">The RFC 8410 algorithm OID, which an RFC 8410 peer <c>SubjectPublicKeyInfo</c> names.</param>
/// <param name="Name">The curve's name, for messages.</param>
/// <param name="Length">The length of a u-coordinate and of the shared secret: 32 bytes for X25519, 56 for X448.</param>
internal sealed record MontgomeryCurve(string Oid, string Name, int Length)
{
    internal static MontgomeryCurve X25519 { get; } = new(Oids.KeyAlgorithms.X25519, "X25519", 32);

    internal static MontgomeryCurve X448 { get; } = new(Oids.KeyAlgorithms.X448, "X448", 56);
}

/// <summary>
/// Validates a peer's X25519 / X448 public key against a local <see cref="CKK.CKK_EC_MONTGOMERY"/> key
/// before it reaches <c>CKM_ECDH1_DERIVE</c>: the peer must be an RFC 8410 <c>SubjectPublicKeyInfo</c>
/// for the local key's curve, its key the curve's length, and its u-coordinate not a low-order point.
/// </summary>
/// <remarks>
/// <para>
/// Every u-coordinate is a valid X25519 / X448 input (RFC 7748 §5), so there is no point to check against a
/// curve equation; the risk is a low-order point, for which the shared secret is all zero whatever the
/// private key. Every such u-coordinate, non-canonical encodings included, is refused here, before the token
/// sees it: the agreement that keeps the secret on the token (<c>Pkcs11Key.DeriveSecretAgreement</c>) has no
/// other chance to catch it. <c>Pkcs11Key.DeriveRawSecret</c> also refuses an all-zero secret the token
/// returns (RFC 7748 §6.1).
/// </para>
/// <para>
/// The curve comes from the local key's <c>CKA_EC_PARAMS</c>, never from the peer: PKCS#11 v3.0 lets it be
/// the RFC 8410 OID or the curve's name as a PrintableString (<c>curve25519</c> / <c>curve448</c>); anything
/// else is not a curve this library can size the secret for. It is read once per key
/// (<c>Pkcs11Key.ResolveMontgomeryCurve</c>).
/// </para>
/// </remarks>
internal static class MontgomeryPeerValidator
{
    // The low-order u-coordinates, little-endian as RFC 7748 encodes them. X25519 (cofactor 8): 0, 1, the
    // two points of order 8, p - 1, and the non-canonical p and p + 1; compared with the top bit masked
    // off, as RFC 7748 §5 has X25519 do, so their top-bit-set encodings are caught too (libsodium's list).
    // X448 (cofactor 4): 0, 1, p - 1 and the non-canonical p and p + 1. Each gives an all-zero secret for
    // every private key.
    private static readonly byte[][] X25519LowOrder =
    [
        Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000"),
        Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000000"),
        Convert.FromHexString("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        Convert.FromHexString("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Convert.FromHexString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Convert.FromHexString("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Convert.FromHexString("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];

    private static readonly byte[][] X448LowOrder =
    [
        new byte[56],
        [0x01, .. new byte[55]],
        // p - 1 = 2^448 - 2^224 - 2, p, p + 1: the low 28 bytes, then the high 28 (byte 28 holds bit 224).
        [0xfe, .. Ones(27), 0xfe, .. Ones(27)],
        [0xff, .. Ones(27), 0xfe, .. Ones(27)],
        [.. new byte[28], 0xff, .. Ones(27)],
    ];

    private static byte[] Ones(int count) => [.. Enumerable.Repeat((byte)0xff, count)];

    /// <summary>Validates <paramref name="peerSubjectPublicKeyInfo"/> against <paramref name="localKey"/>'s curve.</summary>
    /// <param name="localKey">The token-resident Montgomery private key the agreement will use.</param>
    /// <param name="peerSubjectPublicKeyInfo">The peer's public key, as the caller gave it.</param>
    /// <param name="peerParamName">The caller's parameter name, for an argument exception.</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="ArgumentException">The peer is not a DER <c>SubjectPublicKeyInfo</c>, or carries algorithm parameters.</exception>
    /// <exception cref="Pkcs11ArgumentException">The peer's algorithm is not the local key's curve, its key is not that curve's length, or its u-coordinate is a low-order point.</exception>
    /// <exception cref="Pkcs11Exception">The local key's <c>CKA_EC_PARAMS</c> is unreadable or names neither X25519 nor X448.</exception>
    internal static ValidatedMontgomeryPeer Validate(
        Pkcs11Key localKey, ReadOnlySpan<byte> peerSubjectPublicKeyInfo, string peerParamName, string operationName)
    {
        string algorithm = SubjectPublicKeyInfoEncoding.TryReadAlgorithm(peerSubjectPublicKeyInfo)
            ?? throw new ArgumentException("Peer public key is not a DER SubjectPublicKeyInfo.", peerParamName);

        MontgomeryCurve curve = localKey.ResolveMontgomeryCurve(operationName);
        if (!string.Equals(algorithm, curve.Oid, StringComparison.Ordinal))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key algorithm is {algorithm}, expected {curve.Name} {curve.Oid})");

        if (!SubjectPublicKeyInfoEncoding.TryDecodeWithoutParameters(peerSubjectPublicKeyInfo, out _, out byte[]? u))
            throw new ArgumentException(
                $"Peer {curve.Name} public key must have no algorithm parameters (RFC 8410 §3).", peerParamName);

        if (u.Length != curve.Length)
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is {u.Length} bytes; {curve.Name} takes {curve.Length})");

        if (IsLowOrder(u, curve))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is a low-order point: the shared secret would be all zero)");

        return new ValidatedMontgomeryPeer(u, curve.Length);
    }

    /// <summary>
    /// Whether <paramref name="value"/> is all zero, in time independent of its contents. The shared secret
    /// is checked with it after the agreement (RFC 7748 §6.1 asks for a constant-time check there).
    /// </summary>
    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        int accumulator = 0;
        for (int i = 0; i < value.Length; i++)
            accumulator |= value[i];
        return accumulator == 0;
    }

    // Whether u is one of the curve's low-order points. The peer key is public, but the comparison is
    // constant-time anyway, so the check never depends on where a mismatch falls.
    private static bool IsLowOrder(byte[] u, MontgomeryCurve curve)
    {
        bool x25519 = ReferenceEquals(curve, MontgomeryCurve.X25519);
        byte[][] lowOrder = x25519 ? X25519LowOrder : X448LowOrder;
        bool found = false;
        foreach (byte[] point in lowOrder)
        {
            int difference = 0;
            for (int i = 0; i < u.Length; i++)
                difference |= (x25519 && i == u.Length - 1 ? u[i] & 0x7F : u[i]) ^ point[i];
            found |= difference == 0;
        }
        return found;
    }

    /// <summary>The local key's curve, from its <c>CKA_EC_PARAMS</c>. Cached by <c>Pkcs11Key.ResolveMontgomeryCurve</c>.</summary>
    /// <exception cref="Pkcs11Exception">The attribute is unreadable or names neither X25519 nor X448.</exception>
    internal static MontgomeryCurve ReadLocalCurve(Pkcs11Key key, string operationName)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                $"{operationName} (local CKA_EC_PARAMS not readable — cannot tell X25519 from X448)");

        return CurveOf(attrs[0].GetValueAsByteArray()) switch
        {
            Oids.KeyAlgorithms.X25519 => MontgomeryCurve.X25519,
            Oids.KeyAlgorithms.X448 => MontgomeryCurve.X448,
            _ => throw Pkcs11Exception.Create(CKR.CKR_CURVE_NOT_SUPPORTED,
                $"{operationName} (local CKK_EC_MONTGOMERY key's CKA_EC_PARAMS names neither X25519 nor X448)"),
        };
    }

    // The RFC 8410 OID a CKA_EC_PARAMS value names, either as that OID or as the PKCS#11 v3.0 curve name;
    // null for anything else.
    private static string? CurveOf(byte[] ecParams)
    {
        try
        {
            Asn1Tag tag = Asn1Tag.Decode(ecParams, out _);
            if (tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
            {
                string oid = AsnDecoder.ReadObjectIdentifier(ecParams, AsnEncodingRules.DER, out int consumed);
                return consumed == ecParams.Length ? oid : null;
            }
            if (tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.PrintableString)))
            {
                string name = AsnDecoder.ReadCharacterString(ecParams, AsnEncodingRules.DER, UniversalTagNumber.PrintableString, out int consumed);
                if (consumed != ecParams.Length)
                    return null;
                return name switch
                {
                    "curve25519" => Oids.KeyAlgorithms.X25519,
                    "curve448" => Oids.KeyAlgorithms.X448,
                    _ => null,
                };
            }
        }
        catch (AsnContentException)
        {
            // Not DER, or truncated: an unparseable CKA_EC_PARAMS names no curve, the same as an unknown one.
            return null;
        }
        return null;
    }
}
