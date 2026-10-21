using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

/// <summary>
/// Covers <see cref="SubjectPublicKeyInfoEncoding"/> against the BCL's own encoder, and its DER-only
/// reading: a peer key is caller input, so trailing bytes at any level, explicit parameters, and
/// anything but an uncompressed point with equal-length coordinates are refused.
/// </summary>
public sealed class SubjectPublicKeyInfoEncodingTests
{
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
    private const string NistP256Oid = "1.2.840.10045.3.1.7";

    // SEQUENCE { SEQUENCE { algorithm, parameters... }, BIT STRING key }, with optional extra bytes at
    // each level to build the non-canonical inputs.
    private static byte[] Spki(
        string algorithm,
        Action<AsnWriter>? parameters,
        byte[] key,
        int unusedBits = 0,
        byte[]? afterAlgorithm = null,
        byte[]? afterKey = null,
        byte[]? afterSpki = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(algorithm);
                parameters?.Invoke(writer);
                if (afterAlgorithm is not null) writer.WriteEncodedValue(afterAlgorithm);
            }
            writer.WriteBitString(key, unusedBits);
            if (afterKey is not null) writer.WriteEncodedValue(afterKey);
        }
        return afterSpki is null ? writer.Encode() : [.. writer.Encode(), .. afterSpki];
    }

    private static readonly byte[] DerNull = [0x05, 0x00];

    private static Action<AsnWriter> NamedCurve(string oid) => w => w.WriteObjectIdentifier(oid);

    private static byte[] Point(int coordinateLength)
        => [0x04, .. Enumerable.Range(1, 2 * coordinateLength).Select(i => (byte)i)];

    // === Encoding matches the BCL ============================================

    [Fact]
    public void EncodeEc_MatchesTheBcl()
    {
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.Equal(ec.ExportSubjectPublicKeyInfo(), SubjectPublicKeyInfoEncoding.EncodeEc(ec.ExportParameters(false)));
    }

    [Fact]
    public void EncodeRsa_MatchesTheBcl()
    {
        using var rsa = RSA.Create(2048);
        RSAParameters p = rsa.ExportParameters(false);
        Assert.Equal(rsa.ExportSubjectPublicKeyInfo(), SubjectPublicKeyInfoEncoding.EncodeRsa(p.Modulus, p.Exponent));
        Assert.Equal(rsa.ExportRSAPublicKey(), SubjectPublicKeyInfoEncoding.EncodeRsaPublicKey(p.Modulus, p.Exponent));
    }

    // PKCS#11 big integers may carry leading zero bytes; DER INTEGERs are minimal.
    [Fact]
    public void EncodeRsaPublicKey_TrimsLeadingZeros()
    {
        byte[] padded = SubjectPublicKeyInfoEncoding.EncodeRsaPublicKey([0x00, 0x00, 0xC1, 0x02], [0x00, 0x01, 0x00, 0x01]);
        byte[] minimal = SubjectPublicKeyInfoEncoding.EncodeRsaPublicKey([0xC1, 0x02], [0x01, 0x00, 0x01]);

        Assert.Equal(minimal, padded);
        Assert.Equal(new byte[] { 0x30, 0x0A, 0x02, 0x03, 0x00, 0xC1, 0x02, 0x02, 0x03, 0x01, 0x00, 0x01 }, minimal);
    }

    // An all-zero value is the INTEGER 0, not an empty INTEGER.
    [Fact]
    public void EncodeDsaPublicKey_AllZeroValue_IsIntegerZero()
        => Assert.Equal(new byte[] { 0x02, 0x01, 0x00 }, SubjectPublicKeyInfoEncoding.EncodeDsaPublicKey([0x00, 0x00, 0x00]));

    [Fact]
    public void EncodeDsaPublicKey_KeepsANonZeroLeadingByte()
        => Assert.Equal(new byte[] { 0x02, 0x02, 0x01, 0x02 }, SubjectPublicKeyInfoEncoding.EncodeDsaPublicKey([0x01, 0x02]));

    // === TryDecodeEc ==========================================================

    [Fact]
    public void TryDecodeEc_RoundTripsTheBclEncoding()
    {
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters expected = ec.ExportParameters(false);

        Assert.True(SubjectPublicKeyInfoEncoding.TryDecodeEc(ec.ExportSubjectPublicKeyInfo(), out ECParameters decoded));

        Assert.Equal(NistP256Oid, decoded.Curve.Oid.Value);
        Assert.Equal(expected.Q.X, decoded.Q.X);
        Assert.Equal(expected.Q.Y, decoded.Q.Y);
    }

    // The shortest uncompressed point: one byte per coordinate.
    [Fact]
    public void TryDecodeEc_SingleByteCoordinates()
    {
        Assert.True(SubjectPublicKeyInfoEncoding.TryDecodeEc(Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), [0x04, 0xAA, 0xBB]), out ECParameters ec));
        Assert.Equal(new byte[] { 0xAA }, ec.Q.X);
        Assert.Equal(new byte[] { 0xBB }, ec.Q.Y);
    }

    public static TheoryData<string, byte[]> RefusedEcKeys() => new()
    {
        { "not EC", Spki(RsaEncryptionOid, w => w.WriteNull(), Point(32)) },
        { "no parameters", Spki(EcPublicKeyOid, null, Point(32)) },
        { "parameters not an OID", Spki(EcPublicKeyOid, w => w.WriteNull(), Point(32)) },
        { "data after the curve OID", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), Point(32), afterAlgorithm: DerNull) },
        { "compressed point", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), [0x02, .. new byte[32]]) },
        { "point header only", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), [0x04]) },
        { "unequal coordinates", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), Point(32)[..^1]) },
        { "unused bits in the key", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), Point(32), unusedBits: 1) },
        { "data after the key", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), Point(32), afterKey: DerNull) },
        { "data after the SubjectPublicKeyInfo", Spki(EcPublicKeyOid, NamedCurve(NistP256Oid), Point(32), afterSpki: DerNull) },
        { "not DER", [0x30, 0x80, 0x00, 0x00] },
    };

    [Theory]
    [MemberData(nameof(RefusedEcKeys))]
    public void TryDecodeEc_RefusesAnythingElse(string because, byte[] spki)
        => Assert.False(SubjectPublicKeyInfoEncoding.TryDecodeEc(spki, out _), because);

    // === TryReadAlgorithm =====================================================

    [Fact]
    public void TryReadAlgorithm_ReadsTheOid()
        => Assert.Equal(RsaEncryptionOid, SubjectPublicKeyInfoEncoding.TryReadAlgorithm(Spki(RsaEncryptionOid, w => w.WriteNull(), [0x00])));

    [Theory]
    [MemberData(nameof(NonCanonicalSpkis))]
    public void TryReadAlgorithm_NonCanonical_ReturnsNull(string because, byte[] spki)
        => Assert.True(SubjectPublicKeyInfoEncoding.TryReadAlgorithm(spki) is null, because);

    public static TheoryData<string, byte[]> NonCanonicalSpkis() => new()
    {
        { "data after the parameters", Spki(RsaEncryptionOid, w => w.WriteNull(), [0x00], afterAlgorithm: DerNull) },
        { "data after the key", Spki(RsaEncryptionOid, w => w.WriteNull(), [0x00], afterKey: DerNull) },
        { "data after the SubjectPublicKeyInfo", Spki(RsaEncryptionOid, w => w.WriteNull(), [0x00], afterSpki: DerNull) },
        { "unused bits in the key", Spki(RsaEncryptionOid, w => w.WriteNull(), [0x00], unusedBits: 1) },
    };
}
