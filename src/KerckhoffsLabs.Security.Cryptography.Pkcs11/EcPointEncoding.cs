using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// The PKCS#11 encoding of an EC public key, both directions: <c>CKA_EC_POINT</c> is a DER OCTET STRING
/// wrapping the uncompressed point <c>0x04 ‖ X ‖ Y</c>, and <c>CKA_EC_PARAMS</c> is the DER-encoded
/// named-curve OID.
/// </summary>
/// <remarks>
/// Writes DER. Reads BER — a superset that also takes non-minimal lengths and constructed OCTET STRINGs,
/// which some tokens return — but never trailing bytes after the OCTET STRING.
/// </remarks>
internal static class EcPointEncoding
{
    /// <summary>
    /// Encodes an uncompressed EC point (0x04 ‖ X ‖ Y) as a DER OCTET STRING, the form PKCS#11 expects
    /// for <c>CKA_EC_POINT</c> and for the ECDH1 public-data parameter.
    /// </summary>
    internal static byte[] Encode(byte[] x, byte[] y)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString([0x04, .. x, .. y]);
        return writer.Encode();
    }

    /// <summary>
    /// The inverse of <see cref="Encode"/>: splits a <c>CKA_EC_POINT</c> value into its coordinates.
    /// Returns <see langword="false"/> when the bytes aren't an OCTET STRING wrapping an uncompressed point.
    /// </summary>
    internal static bool TryDecode(byte[] ecPoint, out byte[] x, out byte[] y)
    {
        x = y = [];
        if (!TryReadOctetString(ecPoint, out byte[]? point) || point is not [0x04, ..]) return false;

        int coordLen = PointCoordinateLength(point);
        if (coordLen == 0) return false;

        x = point[1..(1 + coordLen)];
        y = point[(1 + coordLen)..];
        return true;
    }

    /// <summary>
    /// Parses raw <c>CKA_EC_POINT</c> + <c>CKA_EC_PARAMS</c> bytes into an <see cref="ECParameters"/>
    /// for a named curve (any curve in <see cref="Pkcs11ECCurve.NamedCurves"/>, and any other named-curve
    /// OID the host BCL recognises). Returns <see langword="null"/> when the inputs don't decode as an
    /// OCTET-STRING-wrapped uncompressed point or <c>CKA_EC_PARAMS</c> isn't a DER-encoded curve OID.
    /// </summary>
    /// <param name="ecPoint">Raw <c>CKA_EC_POINT</c> bytes (OCTET STRING containing the uncompressed point).</param>
    /// <param name="ecParams">Raw <c>CKA_EC_PARAMS</c> bytes (DER-encoded named-curve OID).</param>
    internal static ECParameters? TryParsePublicKey(byte[] ecPoint, byte[] ecParams)
    {
        ArgumentNullException.ThrowIfNull(ecPoint);
        ArgumentNullException.ThrowIfNull(ecParams);

        if (!TryDecode(ecPoint, out byte[] x, out byte[] y)) return null;
        if (ResolveNamedCurve(ecParams) is not { } curve) return null;
        return new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
    }

    /// <summary>
    /// The byte length of one coordinate of the point in a <c>CKA_EC_POINT</c> value — ⌈field bits / 8⌉,
    /// read off the token's own key rather than a curve table. Accepts the conformant OCTET STRING
    /// form and, for tokens that omit the wrapper, the bare point; uncompressed (<c>0x04 ‖ X ‖ Y</c>) or
    /// compressed (<c>0x02/0x03 ‖ X</c>). Returns <see langword="false"/> when neither form parses.
    /// </summary>
    /// <remarks>
    /// The OCTET STRING form wins whenever it parses. A bare point misread as one needs its first
    /// coordinate bytes to forge both a matching length and a point header, and even then the result is a
    /// wrong size, which the ECDH coordinate-length check turns into a refusal.
    /// </remarks>
    internal static bool TryGetCoordinateLength(byte[] ecPoint, out int coordinateLength)
    {
        ArgumentNullException.ThrowIfNull(ecPoint);

        coordinateLength = TryReadOctetString(ecPoint, out byte[]? point) ? PointCoordinateLength(point) : 0;
        if (coordinateLength == 0)
            coordinateLength = PointCoordinateLength(ecPoint);
        return coordinateLength > 0;
    }

    private static int PointCoordinateLength(ReadOnlySpan<byte> point) => point switch
    {
        [0x04, ..] when point.Length >= 3 && point.Length % 2 == 1 => (point.Length - 1) / 2,
        [0x02 or 0x03, ..] when point.Length >= 2 => point.Length - 1,
        _ => 0,
    };

    private static bool TryReadOctetString(byte[] encoded, [NotNullWhen(true)] out byte[]? content)
    {
        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.BER);
            content = reader.ReadOctetString();
            reader.ThrowIfNotEmpty();
            return true;
        }
        catch (AsnContentException)
        {
            content = null;
            return false;
        }
    }

    // CKA_EC_PARAMS for a named curve is the DER-encoded curve OID; bridge it to a BCL named curve
    // over that OID. Covers the whole Pkcs11ECCurve.NamedCurves catalog (NIST, secp256k1, Brainpool, SM2),
    // not just the NIST primes. Returns null when the bytes aren't a DER-encoded OID.
    private static ECCurve? ResolveNamedCurve(byte[] derOid)
    {
        try
        {
            return Pkcs11ECCurve.FromEcParams(derOid).ToECCurve();
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
