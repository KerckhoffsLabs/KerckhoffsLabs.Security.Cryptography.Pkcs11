using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers Pkcs11PublicKeyView.TryParseEcPublicKey: building an ECParameters view from raw CKA_EC_POINT
// + CKA_EC_PARAMS. Since the curve is resolved through ECCurve.FromEcParams, the whole named-curve
// catalog is supported — not just the NIST primes the helper used to hardcode. The point bytes are
// only parsed for structure (not validated on-curve), so synthetic coordinates are fine here.
public sealed class Pkcs11PublicKeyViewTests
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
    public void TryParseEcPublicKey_ResolvesNamedCurveFromEcParams(string curveName, int coordLen)
    {
        ECCurve curve = ECCurve.CreateFromFriendlyName(curveName);
        byte[] ecParams = curve.GetEcParams();
        byte[] ecPoint = EcPoint(coordLen);

        ECParameters? parsed = Pkcs11PublicKeyView.TryParseEcPublicKey(ecPoint, ecParams);

        Assert.NotNull(parsed);
        Assert.True(parsed!.Value.Curve.IsNamed);
        Assert.Equal(curve.Oid, parsed.Value.Curve.Oid.Value);
        Assert.Equal(coordLen, parsed.Value.Q.X!.Length);
        Assert.Equal(coordLen, parsed.Value.Q.Y!.Length);
    }

    [Fact]
    public void TryParseEcPublicKey_MalformedEcParams_ReturnsNull()
    {
        byte[] ecPoint = EcPoint(coordLen: 32);
        Assert.Null(Pkcs11PublicKeyView.TryParseEcPublicKey(ecPoint, [0x01, 0x02, 0x03]));
    }

    [Fact]
    public void TryParseEcPublicKey_NonUncompressedPoint_ReturnsNull()
    {
        // 0x02-prefixed compressed point is not supported by the uncompressed-only parser.
        byte[] ecParams = ECCurve.NamedCurves.NistP256.GetEcParams();
        byte[] compressed = [0x04, 0x21, 0x02, .. new byte[32]];
        Assert.Null(Pkcs11PublicKeyView.TryParseEcPublicKey(compressed, ecParams));
    }
}
