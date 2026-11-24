using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// The parse behind the EC adapters' <c>ExportParameters(false)</c>. Over a token it only ever reads what
/// <c>Pkcs11Key.Export</c> writes, a named-curve RFC 5480 <c>SubjectPublicKeyInfo</c>; these tests hand it
/// that encoding from the BCL, and the encodings Export never writes, which must fail as a
/// <see cref="CryptographicException"/> rather than leak an ASN.1 reader exception.
/// </summary>
public sealed class EcSubjectPublicKeyInfoTests
{
    [Fact]
    public void NamedCurveSpki_GivesTheCurveAndPoint()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters expected = ecdsa.ExportParameters(false);

        ECParameters parsed = EcSubjectPublicKeyInfo.FromSubjectPublicKeyInfo(ecdsa.ExportSubjectPublicKeyInfo());

        Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, parsed.Curve.Oid.Value);
        Assert.Equal(expected.Q.X, parsed.Q.X);
        Assert.Equal(expected.Q.Y, parsed.Q.Y);
    }

    // Explicit domain parameters put a SEQUENCE where the curve's OID is read. Written by hand: macOS's ECDsa
    // exports named curves only (PlatformNotSupportedException), and only the parameters' tag matters here.
    [Fact]
    public void ExplicitCurveSpki_ThrowsCryptographicException()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECPoint q = ecdsa.ExportParameters(false).Q;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.10045.2.1");    // id-ecPublicKey
                using (writer.PushSequence())                       // SpecifiedECDomain, abridged
                    writer.WriteInteger(1);
            }
            writer.WriteBitString([0x04, .. q.X!, .. q.Y!]);
        }

        AssertMalformed(writer.Encode());
    }

    [Fact]
    public void TruncatedSpki_ThrowsCryptographicException()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = ecdsa.ExportSubjectPublicKeyInfo();

        AssertMalformed(spki[..^1]);
    }

    private static void AssertMalformed(byte[] spki)
    {
        var ex = Assert.Throws<CryptographicException>(() => EcSubjectPublicKeyInfo.FromSubjectPublicKeyInfo(spki));
        Assert.Contains("malformed EC SubjectPublicKeyInfo", ex.Message, StringComparison.Ordinal);
        Assert.IsType<AsnContentException>(ex.InnerException);
    }
}
