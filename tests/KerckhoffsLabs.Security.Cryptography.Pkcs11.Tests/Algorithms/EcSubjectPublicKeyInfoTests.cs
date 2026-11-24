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

    // Explicit domain parameters put a SEQUENCE where the curve's OID is read.
    [Fact]
    public void ExplicitCurveSpki_ThrowsCryptographicException()
    {
        using var named = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(named.ExportExplicitParameters(false));

        AssertMalformed(ecdsa.ExportSubjectPublicKeyInfo());
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
