using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers EcPointEncoding: the CKA_EC_POINT encoder/decoder pair, and TryParsePublicKey building an ECParameters view from raw CKA_EC_POINT
// + CKA_EC_PARAMS. Since the curve is resolved through Pkcs11ECCurve.FromEcParams, the whole named-curve
// catalog is supported — not just the NIST primes the helper used to hardcode. The point bytes are
// only parsed for structure (not validated on-curve), so synthetic coordinates are fine here.
public sealed class EcPointEncodingTests
{
    // CKA_EC_POINT is a DER OCTET STRING wrapping the uncompressed point 0x04 || X || Y.
    private static byte[] EcPoint(int coordLen)
    {
        byte[] point = new byte[1 + 2 * coordLen];
        point[0] = 0x04;
        for (int i = 1; i < point.Length; i++) point[i] = (byte)(i & 0xFF);
        return DerOctetString(point);
    }

    private static byte[] DerOctetString(byte[] content) =>
        content.Length <= 0x7F
            ? [0x04, (byte)content.Length, .. content]
            : [0x04, 0x81, (byte)content.Length, .. content]; // long-form length (fits one byte up to 255)

    [Theory]
    [InlineData("nistP256", 32)]      // previously hardcoded
    [InlineData("secp256k1", 32)]     // previously unsupported -> returned a broken default curve
    [InlineData("brainpoolP256r1", 32)]
    [InlineData("nistP521", 66)]      // 133-byte point -> exercises the long-form DER length branch
    public void TryParsePublicKey_ResolvesNamedCurveFromEcParams(string curveName, int coordLen)
    {
        Pkcs11ECCurve curve = Pkcs11ECCurve.CreateFromFriendlyName(curveName);
        byte[] ecParams = curve.GetEcParams();
        byte[] ecPoint = EcPoint(coordLen);

        ECParameters? parsed = EcPointEncoding.TryParsePublicKey(ecPoint, ecParams);

        Assert.NotNull(parsed);
        Assert.True(parsed!.Value.Curve.IsNamed);
        Assert.Equal(curve.Oid, parsed!.Value.Curve.Oid.Value);
        Assert.Equal(coordLen, parsed!.Value.Q.X!.Length);
        Assert.Equal(coordLen, parsed!.Value.Q.Y!.Length);
    }

    [Fact]
    public void TryParsePublicKey_MalformedEcParams_ReturnsNull()
    {
        byte[] ecPoint = EcPoint(coordLen: 32);
        Assert.Null(EcPointEncoding.TryParsePublicKey(ecPoint, [0x01, 0x02, 0x03]));
    }

    [Fact]
    public void TryParsePublicKey_NonUncompressedPoint_ReturnsNull()
    {
        // 0x02-prefixed compressed point is not supported by the uncompressed-only parser.
        byte[] ecParams = Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams();
        byte[] compressed = [0x04, 0x21, 0x02, .. new byte[32]];
        Assert.Null(EcPointEncoding.TryParsePublicKey(compressed, ecParams));
    }

    [Theory]
    [InlineData(32)]  // short-form DER length
    [InlineData(66)]  // 133-byte point: long-form DER length
    public void Encode_RoundTripsThroughTryDecode(int coordLen)
    {
        byte[] x = [.. Enumerable.Range(1, coordLen).Select(i => (byte)i)];
        byte[] y = [.. Enumerable.Range(100, coordLen).Select(i => (byte)i)];

        byte[] encoded = EcPointEncoding.Encode(x, y);

        Assert.Equal(EcPoint(coordLen)[..2], encoded[..2]);
        Assert.True(EcPointEncoding.TryDecode(encoded, out byte[] decodedX, out byte[] decodedY));
        Assert.Equal(x, decodedX);
        Assert.Equal(y, decodedY);
    }

    [Fact]
    public void TryDecode_NotAnOctetString_ReturnsFalse()
        => Assert.False(EcPointEncoding.TryDecode([0x03, 0x01, 0x04], out _, out _));

    // 128-byte coordinates make a 257-byte point, past the old encoder's one-byte long-form length.
    [Fact]
    public void Encode_PointOver255Bytes_UsesTwoByteLength()
    {
        byte[] x = new byte[128], y = new byte[128];
        x[0] = 1; y[^1] = 2;

        byte[] encoded = EcPointEncoding.Encode(x, y);

        Assert.Equal(new byte[] { 0x04, 0x82, 0x01, 0x01, 0x04 }, encoded[..5]);
        Assert.True(EcPointEncoding.TryDecode(encoded, out byte[] decodedX, out byte[] decodedY));
        Assert.Equal(x, decodedX);
        Assert.Equal(y, decodedY);
    }

    // Read as BER: a token that pads the length (0x81 for a length under 128) is still understood.
    [Fact]
    public void TryDecode_NonMinimalLength_Accepted()
    {
        byte[] point = EcPoint(32)[2..];
        Assert.True(EcPointEncoding.TryDecode([0x04, 0x81, (byte)point.Length, .. point], out byte[] x, out _));
        Assert.Equal(point[1..33], x);
    }

    // BER also allows a constructed OCTET STRING (indefinite length, split into segments).
    [Fact]
    public void TryDecode_ConstructedOctetString_Accepted()
    {
        byte[] point = EcPoint(32)[2..];
        byte[] ber = [0x24, 0x80, 0x04, 0x20, .. point[..32], 0x04, (byte)(point.Length - 32), .. point[32..], 0x00, 0x00];

        Assert.True(EcPointEncoding.TryDecode(ber, out byte[] x, out byte[] y));
        Assert.Equal(point[1..33], x);
        Assert.Equal(point[33..], y);
    }

    // The old parser ignored anything after the OCTET STRING.
    [Fact]
    public void TryDecode_TrailingBytes_ReturnsFalse()
        => Assert.False(EcPointEncoding.TryDecode([.. EcPoint(32), 0x00], out _, out _));

    [Theory]
    [InlineData(30)]
    [InlineData(32)]
    [InlineData(66)] // long-form DER length
    public void TryGetCoordinateLength_DerUncompressed(int coordLen)
    {
        Assert.True(EcPointEncoding.TryGetCoordinateLength(EcPoint(coordLen), out int length));
        Assert.Equal(coordLen, length);
    }

    // Some tokens return the bare point without the DER OCTET STRING wrapper.
    [Theory]
    [InlineData(32)]
    [InlineData(66)]
    public void TryGetCoordinateLength_BareUncompressed(int coordLen)
    {
        byte[] bare = EcPoint(coordLen)[(coordLen * 2 + 1 <= 0x7F ? 2 : 3)..];
        Assert.True(EcPointEncoding.TryGetCoordinateLength(bare, out int length));
        Assert.Equal(coordLen, length);
    }

    [Theory]
    [InlineData(0x02)]
    [InlineData(0x03)]
    public void TryGetCoordinateLength_DerCompressed(byte prefix)
    {
        byte[] compressed = [prefix, .. new byte[32]];
        Assert.True(EcPointEncoding.TryGetCoordinateLength(DerOctetString(compressed), out int length));
        Assert.Equal(32, length);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0x04 })]
    [InlineData(new byte[] { 0x04, 0x02, 0x04, 0x00 })] // even-length point, wrapped or bare
    [InlineData(new byte[] { 0x05, 0x01, 0x02, 0x03 })] // neither an OCTET STRING nor a point header
    public void TryGetCoordinateLength_Malformed_ReturnsFalse(byte[] ecPoint)
        => Assert.False(EcPointEncoding.TryGetCoordinateLength(ecPoint, out _));
}
