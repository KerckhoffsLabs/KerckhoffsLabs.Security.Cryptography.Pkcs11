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

/// <summary>
/// Validates a peer's X25519 / X448 public key against a local <see cref="CKK.CKK_EC_MONTGOMERY"/> key
/// before it reaches <c>CKM_ECDH1_DERIVE</c>: the peer must be an RFC 8410 <c>SubjectPublicKeyInfo</c>
/// for the local key's curve, its key the curve's length, and its u-coordinate not zero.
/// </summary>
/// <remarks>
/// <para>
/// Every u-coordinate is a valid X25519 / X448 input (RFC 7748 §5), so there is no point to check against a
/// curve equation; the risk is a low-order point, for which the shared secret is all zero whatever the
/// private key. u = 0 is refused here, before the token sees it. The other low-order points (and
/// non-canonical encodings of them) give the same all-zero secret, which <c>Pkcs11Key.DeriveRawSecret</c>
/// refuses once the token returns it (RFC 7748 §6.1: check for the all-zero value).
/// </para>
/// <para>
/// The curve comes from the local key's <c>CKA_EC_PARAMS</c>, never from the peer: PKCS#11 v3.0 lets it be
/// the RFC 8410 OID or the curve's name as a PrintableString (<c>curve25519</c> / <c>curve448</c>); anything
/// else is not a curve this library can size the secret for.
/// </para>
/// </remarks>
internal static class MontgomeryPeerValidator
{
    private const int X25519Length = 32;
    private const int X448Length = 56;

    /// <summary>Validates <paramref name="peerSubjectPublicKeyInfo"/> against <paramref name="localKey"/>'s curve.</summary>
    /// <param name="localKey">The token-resident Montgomery private key the agreement will use.</param>
    /// <param name="peerSubjectPublicKeyInfo">The peer's public key, as the caller gave it.</param>
    /// <param name="peerParamName">The caller's parameter name, for an argument exception.</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="ArgumentException">The peer is not a DER <c>SubjectPublicKeyInfo</c>, or carries algorithm parameters.</exception>
    /// <exception cref="Pkcs11ArgumentException">The peer's algorithm is not the local key's curve, its key is not that curve's length, or its u-coordinate is zero.</exception>
    /// <exception cref="Pkcs11Exception">The local key's <c>CKA_EC_PARAMS</c> is unreadable or names neither X25519 nor X448.</exception>
    internal static ValidatedMontgomeryPeer Validate(
        Pkcs11Key localKey, ReadOnlySpan<byte> peerSubjectPublicKeyInfo, string peerParamName, string operationName)
    {
        string algorithm = SubjectPublicKeyInfoEncoding.TryReadAlgorithm(peerSubjectPublicKeyInfo)
            ?? throw new ArgumentException("Peer public key is not a DER SubjectPublicKeyInfo.", peerParamName);

        (string localOid, int length) = ReadLocalCurve(localKey, operationName);
        if (!string.Equals(algorithm, localOid, StringComparison.Ordinal))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key algorithm is {algorithm}, expected {Name(localOid)} {localOid})");

        if (!SubjectPublicKeyInfoEncoding.TryDecodeWithoutParameters(peerSubjectPublicKeyInfo, out _, out byte[]? u))
            throw new ArgumentException(
                $"Peer {Name(localOid)} public key must have no algorithm parameters (RFC 8410 §3).", peerParamName);

        if (u.Length != length)
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is {u.Length} bytes; {Name(localOid)} takes {length})");

        if (IsZero(u, maskTopBit: length == X25519Length))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is u = 0, a low-order point: the shared secret would be all zero)");

        return new ValidatedMontgomeryPeer(u, length);
    }

    /// <summary>
    /// Whether <paramref name="value"/> is all zero, in time independent of its contents. The shared secret
    /// is checked with it after the agreement (RFC 7748 §6.1 asks for a constant-time check there).
    /// </summary>
    /// <param name="value">The bytes to check.</param>
    /// <param name="maskTopBit">
    /// Ignore the top bit of the last byte: X25519 masks it off a u-coordinate before use (RFC 7748 §5), so
    /// <c>00…80</c> is u = 0 too.
    /// </param>
    internal static bool IsZero(ReadOnlySpan<byte> value, bool maskTopBit = false)
    {
        int accumulator = 0;
        for (int i = 0; i < value.Length; i++)
            accumulator |= maskTopBit && i == value.Length - 1 ? value[i] & 0x7F : value[i];
        return accumulator == 0;
    }

    private static string Name(string oid) => oid == Oids.KeyAlgorithms.X25519 ? "X25519" : "X448";

    // The local key's curve and secret length, from its CKA_EC_PARAMS.
    private static (string Oid, int Length) ReadLocalCurve(Pkcs11Key key, string operationName)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                $"{operationName} (local CKA_EC_PARAMS not readable — cannot tell X25519 from X448)");

        return CurveOf(attrs[0].GetValueAsByteArray()) switch
        {
            Oids.KeyAlgorithms.X25519 => (Oids.KeyAlgorithms.X25519, X25519Length),
            Oids.KeyAlgorithms.X448 => (Oids.KeyAlgorithms.X448, X448Length),
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
        }
        return null;
    }
}
