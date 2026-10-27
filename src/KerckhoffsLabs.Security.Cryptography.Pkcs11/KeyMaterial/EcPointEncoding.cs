using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// The PKCS#11 encoding of an EC public key, both directions: <c>CKA_EC_POINT</c> is a DER OCTET STRING
/// wrapping the uncompressed point <c>0x04 ‖ X ‖ Y</c>, and <c>CKA_EC_PARAMS</c> is the DER-encoded
/// named-curve OID.
/// </summary>
/// <remarks>
/// Writes DER. Reads a primitive OCTET STRING with BER lengths, so a token that pads the length
/// (<c>0x81</c> for one under 128) is still understood; but never a constructed OCTET STRING, segmented
/// or of indefinite length, which would let a token assemble the point from fragments, and never
/// trailing bytes after the OCTET STRING.
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
        writer.WriteOctetString(EncodeUncompressedPoint(x, y));
        return writer.Encode();
    }

    /// <summary>
    /// The inverse of <see cref="Encode"/>: splits a <c>CKA_EC_POINT</c> value into its coordinates.
    /// Returns <see langword="false"/> when the bytes aren't an OCTET STRING wrapping an uncompressed point.
    /// </summary>
    internal static bool TryDecode(byte[] ecPoint, out byte[] x, out byte[] y)
    {
        x = y = [];
        return TryReadOctetString(ecPoint, out byte[]? point) && TrySplitUncompressedPoint(point, out x, out y);
    }

    /// <summary>The bare uncompressed point <c>0x04 ‖ X ‖ Y</c> (SEC 1 §2.3.3), without the OCTET STRING.</summary>
    internal static byte[] EncodeUncompressedPoint(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y) => [0x04, .. x, .. y];

    /// <summary>
    /// The inverse of <see cref="EncodeUncompressedPoint"/>. Returns <see langword="false"/> unless
    /// <paramref name="point"/> is <c>0x04</c> followed by two non-empty coordinates of equal length.
    /// </summary>
    internal static bool TrySplitUncompressedPoint(ReadOnlySpan<byte> point, out byte[] x, out byte[] y)
    {
        x = y = [];
        if (point is not [0x04, ..] || PointCoordinateLength(point) is not (> 0 and var coordinateLength)) return false;

        x = point.Slice(1, coordinateLength).ToArray();
        y = point[(1 + coordinateLength)..].ToArray();
        return true;
    }

    /// <summary>
    /// Parses raw <c>CKA_EC_POINT</c> + <c>CKA_EC_PARAMS</c> bytes into an <see cref="ECParameters"/>
    /// for a named curve (any curve in <see cref="Pkcs11ECCurve.NamedCurves"/>, and any other named-curve
    /// OID the host BCL recognises). Returns <see langword="false"/> when the inputs don't decode as an
    /// OCTET-STRING-wrapped uncompressed point or <c>CKA_EC_PARAMS</c> isn't a DER-encoded curve OID.
    /// </summary>
    /// <param name="ecPoint">Raw <c>CKA_EC_POINT</c> bytes (OCTET STRING containing the uncompressed point).</param>
    /// <param name="ecParams">Raw <c>CKA_EC_PARAMS</c> bytes (DER-encoded named-curve OID).</param>
    /// <param name="ec">The public key, when the method returns <see langword="true"/>.</param>
    internal static bool TryParsePublicKey(byte[] ecPoint, byte[] ecParams, out ECParameters ec)
    {
        ArgumentNullException.ThrowIfNull(ecPoint);
        ArgumentNullException.ThrowIfNull(ecParams);

        ec = default;
        if (!TryDecode(ecPoint, out byte[] x, out byte[] y) || !TryResolveNamedCurve(ecParams, out ECCurve curve)) return false;
        ec = new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
        return true;
    }

    /// <summary>
    /// Resolves a <c>CKA_EC_PARAMS</c> value, or an EC <c>SubjectPublicKeyInfo</c>'s <i>namedCurve</i>
    /// parameters (the same DER-encoded OID), to a BCL named curve over that OID. Returns
    /// <see langword="false"/> unless the bytes are exactly one DER-encoded OID.
    /// </summary>
    internal static bool TryResolveNamedCurve(ReadOnlySpan<byte> ecParams, out ECCurve curve)
    {
        try
        {
            curve = Pkcs11ECCurve.FromEcParams(ecParams).ToECCurve();
            return true;
        }
        catch (ArgumentException)
        {
            curve = default;
            return false;
        }
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
        // The primitive tag only: BER allows an indefinite length on a constructed encoding alone.
        if (encoded is not [0x04, ..])
        {
            content = null;
            return false;
        }

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
}
