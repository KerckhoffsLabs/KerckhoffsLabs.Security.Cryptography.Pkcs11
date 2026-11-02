using System.Formats.Asn1;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>An RFC 8410 curve: Ed25519, Ed448, X25519 or X448.</summary>
/// <param name="Oid">The RFC 8410 algorithm OID, the <c>AlgorithmIdentifier</c> of the key's <c>SubjectPublicKeyInfo</c>.</param>
/// <param name="Name">The curve's name, for messages.</param>
/// <param name="KeyLength">The length of a public key, RFC 8032 / RFC 7748 encoded: 32, 57, 32 and 56 bytes.</param>
/// <param name="KeyType">The key type of the curve's keys: <see cref="CKK.CKK_EC_EDWARDS"/> or <see cref="CKK.CKK_EC_MONTGOMERY"/>.</param>
internal sealed record Rfc8410Curve(string Oid, string Name, int KeyLength, CKK KeyType);

/// <summary>
/// The curves of <see cref="CKK.CKK_EC_EDWARDS"/> and <see cref="CKK.CKK_EC_MONTGOMERY"/> keys, read off a
/// key's <c>CKA_EC_PARAMS</c>.
/// </summary>
/// <remarks>
/// PKCS#11 v3.0 lets <c>CKA_EC_PARAMS</c> of these keys be the curve's RFC 8410 OID or its name as a
/// PrintableString: <c>edwards25519</c> / <c>edwards448</c> for Edwards keys, <c>curve25519</c> /
/// <c>curve448</c> for Montgomery keys. Either form must be the whole value, in DER. A curve of the other
/// family names no curve for the key: an Edwards key on X25519 is not a key this library can describe.
/// </remarks>
internal static class Rfc8410Curves
{
    internal static Rfc8410Curve Ed25519 { get; } = new(Oids.KeyAlgorithms.Ed25519, "Ed25519", 32, CKK.CKK_EC_EDWARDS);

    internal static Rfc8410Curve Ed448 { get; } = new(Oids.KeyAlgorithms.Ed448, "Ed448", 57, CKK.CKK_EC_EDWARDS);

    internal static Rfc8410Curve X25519 { get; } = new(Oids.KeyAlgorithms.X25519, "X25519", 32, CKK.CKK_EC_MONTGOMERY);

    internal static Rfc8410Curve X448 { get; } = new(Oids.KeyAlgorithms.X448, "X448", 56, CKK.CKK_EC_MONTGOMERY);

    /// <summary>
    /// The curve <paramref name="ecParams"/> names for a key of <paramref name="keyType"/>, or
    /// <see langword="null"/> when it names none of that key type's curves or is not DER.
    /// </summary>
    internal static Rfc8410Curve? Describe(CKK keyType, ReadOnlySpan<byte> ecParams)
        => Read(ecParams) is { } curve && curve.KeyType == keyType ? curve : null;

    // The curve the value names, by OID or by PKCS#11 name, exactly and in DER; null for anything else.
    private static Rfc8410Curve? Read(ReadOnlySpan<byte> ecParams)
    {
        if (!Asn1Tag.TryDecode(ecParams, out Asn1Tag tag, out _))
            return null;
        try
        {
            int consumed;
            Rfc8410Curve? curve;
            if (tag == Asn1Tag.ObjectIdentifier)
            {
                curve = AsnDecoder.ReadObjectIdentifier(ecParams, AsnEncodingRules.DER, out consumed) switch
                {
                    Oids.KeyAlgorithms.Ed25519 => Ed25519,
                    Oids.KeyAlgorithms.Ed448 => Ed448,
                    Oids.KeyAlgorithms.X25519 => X25519,
                    Oids.KeyAlgorithms.X448 => X448,
                    _ => null,
                };
            }
            else if (tag == new Asn1Tag(UniversalTagNumber.PrintableString))
            {
                curve = AsnDecoder.ReadCharacterString(ecParams, AsnEncodingRules.DER, UniversalTagNumber.PrintableString, out consumed) switch
                {
                    "edwards25519" => Ed25519,
                    "edwards448" => Ed448,
                    "curve25519" => X25519,
                    "curve448" => X448,
                    _ => null,
                };
            }
            else
            {
                return null;
            }
            return consumed == ecParams.Length ? curve : null;
        }
        catch (AsnContentException)
        {
            // Not DER, or truncated: names no curve, the same as an unknown one.
            return null;
        }
    }
}
