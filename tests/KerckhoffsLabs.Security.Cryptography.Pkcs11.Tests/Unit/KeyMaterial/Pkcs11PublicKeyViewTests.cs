using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

/// <summary>
/// <see cref="Pkcs11PublicKeyView.ReadEcPublicKey"/> over a fake token that answers <c>CKA_EC_POINT</c> and
/// <c>CKA_EC_PARAMS</c> as each test says: a well-formed pair becomes the key's <see cref="ECParameters"/>,
/// an unreadable attribute is <see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>, and bytes that are not a named
/// curve and an uncompressed point are <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/>. A real token never
/// returns the failure cases for a well-formed key, so only the fake reaches them.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11PublicKeyViewTests
{
    private const string Operation = "Pkcs11PublicKeyViewTests.Read";

    private static readonly ECParameters Expected = Generate();

    private static ECParameters Generate()
    {
        // The parsing under test needs only well-formed bytes; any P-256 point will do, and the coordinates
        // are fixed so the class needs no platform EC support.
        byte[] x = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
        byte[] y = [.. Enumerable.Range(33, 32).Select(i => (byte)i)];
        return new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
    }

    private static readonly byte[] ValidPoint = EcPointEncoding.Encode(Expected.Q.X!, Expected.Q.Y!);
    private static readonly byte[] ValidParams = Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams();

    private static FakeKey EcKey(byte[]? point, byte[]? parameters) => FakeKeys.Create(CKK.CKK_EC, ca => ca switch
    {
        CKA.CKA_EC_POINT => point is null ? (CKR.CKR_ATTRIBUTE_SENSITIVE, null) : (CKR.CKR_OK, point),
        CKA.CKA_EC_PARAMS => parameters is null ? (CKR.CKR_ATTRIBUTE_SENSITIVE, null) : (CKR.CKR_OK, parameters),
        _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
    });

    [Fact]
    public void WellFormedAttributes_AreTheKeysPublicParameters()
    {
        using var key = EcKey(ValidPoint, ValidParams);

        ECParameters read = Pkcs11PublicKeyView.ReadEcPublicKey(key, Operation);

        Assert.Equal(Expected.Curve.Oid.Value, read.Curve.Oid.Value);
        Assert.Equal(Expected.Q.X, read.Q.X);
        Assert.Equal(Expected.Q.Y, read.Q.Y);
        Assert.Null(read.D);
    }

    // Each attribute on its own, then both: either one unreadable is enough to refuse.
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public void UnreadableAttribute_IsSensitive(bool pointReadable, bool paramsReadable)
    {
        using var key = EcKey(pointReadable ? ValidPoint : null, paramsReadable ? ValidParams : null);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Pkcs11PublicKeyView.ReadEcPublicKey(key, Operation));
        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
        Assert.Contains(Operation, ex.Message);
    }

    public static TheoryData<string, byte[], byte[]> Malformed => new()
    {
        // Not an OCTET STRING around the point.
        { "point not an OCTET STRING", [0x01, 0x02, 0x03], Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams() },
        // An OCTET STRING, but around a compressed point: only the uncompressed form is accepted.
        { "compressed point", [0x04, 0x03, 0x02, 0xAA, 0xBB], Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams() },
        // Explicit curve parameters (a SEQUENCE), not a named-curve OID.
        { "params not an OID", EcPointEncoding.Encode(new byte[32], new byte[32]), [0x30, 0x00] },
    };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void MalformedAttributes_AreInvalid(string because, byte[] point, byte[] parameters)
    {
        using var key = EcKey(point, parameters);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Pkcs11PublicKeyView.ReadEcPublicKey(key, Operation));
        Assert.True(ex.ReturnValue == CKR.CKR_ATTRIBUTE_VALUE_INVALID, because);
        Assert.Contains(Operation, ex.Message);
    }

    // The public way in: Pkcs11Key.Export reports the same failure under its own name.
    [Fact]
    public void Export_ReportsTheFailureUnderItsOwnName()
    {
        using var key = EcKey(null, ValidParams);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
        Assert.Contains("Pkcs11Key.Export", ex.Message);
    }
}
