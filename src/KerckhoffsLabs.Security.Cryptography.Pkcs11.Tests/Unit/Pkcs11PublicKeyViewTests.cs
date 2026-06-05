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

        byte[] der = new byte[2 + point.Length];
        der[0] = 0x04;
        der[1] = (byte)point.Length; // coordLen 32 -> 65 bytes, fits a single short-form length byte
        point.CopyTo(der, 2);
        return der;
    }

    [Theory]
    [InlineData("nistP256")]      // previously hardcoded
    [InlineData("secp256k1")]     // previously unsupported -> returned a broken default curve
    [InlineData("brainpoolP256r1")]
    public void TryParseEcPublicKey_ResolvesNamedCurveFromEcParams(string curveName)
    {
        ECCurve curve = ECCurve.CreateFromFriendlyName(curveName);
        byte[] ecParams = curve.EcParams;
        byte[] ecPoint = EcPoint(coordLen: 32);

        ECParameters? parsed = Pkcs11PublicKeyView.TryParseEcPublicKey(ecPoint, ecParams);

        Assert.NotNull(parsed);
        Assert.True(parsed.Value.Curve.IsNamed);
        Assert.Equal(curve.Oid, parsed.Value.Curve.Oid.Value);
        Assert.Equal(32, parsed.Value.Q.X!.Length);
        Assert.Equal(32, parsed.Value.Q.Y!.Length);
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
        byte[] ecParams = ECCurve.NamedCurves.NistP256.EcParams;
        byte[] compressed = [0x04, 0x21, 0x02, .. new byte[32]];
        Assert.Null(Pkcs11PublicKeyView.TryParseEcPublicKey(compressed, ecParams));
    }
}
