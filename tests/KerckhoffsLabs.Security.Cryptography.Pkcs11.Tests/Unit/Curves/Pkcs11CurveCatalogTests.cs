using System.Numerics;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Curves;

// Covers Pkcs11CurveCatalog / Pkcs11CurveInfo: the built-in catalog, extension with With, lookups,
// resolving a bare curve read off a token, and how a library picks its catalog up from the options.
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11CurveCatalogTests
{
    private const string Prime239v1Oid = "1.2.840.10045.3.1.4";
    private static readonly Pkcs11CurveInfo Prime239v1 = new(Prime239v1Oid, "prime239v1", 239);

    [Fact]
    public void Default_ListsP256()
    {
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByOid("1.2.840.10045.3.1.7", out Pkcs11CurveInfo? info));
        Assert.Equal("nistP256", info.Name);
        Assert.Equal(256, info.FieldSizeBits);
    }

    // The group order of these curves is just above a power of two, one bit past the field: an ECDSA r or s
    // can take one byte more than a coordinate.
    [Theory]
    [InlineData("secp160k1", 160, 161)]
    [InlineData("secp160r1", 160, 161)]
    [InlineData("secp160r2", 160, 161)]
    [InlineData("secp224k1", 224, 225)]
    [InlineData("nistP256", 256, 256)]
    [InlineData("nistP521", 521, 521)]
    public void Default_OrderSize_IsTheStandardCurves(string name, int fieldSizeBits, int orderSizeBits)
    {
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByName(name, out Pkcs11CurveInfo? info));
        Assert.Equal(fieldSizeBits, info.FieldSizeBits);
        Assert.Equal(orderSizeBits, info.OrderSizeBits);
    }

    // The field size is the KeySize the BCL reports for the curve, and the order size is the bit length of
    // the order it exports. Checked on every built-in curve this platform's BCL implements.
    [Fact]
    public void Default_EveryCurve_MatchesTheBcl()
    {
        int checkedCurves = 0;
        foreach (Pkcs11CurveInfo info in Pkcs11CurveCatalog.Default.Curves)
        {
            ECDsa ec;
            try
            {
                ec = ECDsa.Create(ECCurve.CreateFromValue(info.Oid));
            }
            catch (Exception e) when (e is PlatformNotSupportedException or CryptographicException)
            {
                continue; // a curve this platform's BCL doesn't implement
            }

            using (ec)
            {
                byte[] order = ec.ExportExplicitParameters(includePrivateParameters: false).Curve.Order!;
                long orderBits = new BigInteger(order, isUnsigned: true, isBigEndian: true).GetBitLength();
                Assert.True(ec.KeySize == info.FieldSizeBits, $"{info.Name}: the BCL's KeySize is {ec.KeySize}.");
                Assert.True(orderBits == info.OrderSizeBits, $"{info.Name}: the BCL's order is {orderBits} bits.");
            }
            checkedCurves++;
        }

        Assert.True(checkedCurves > 0);
    }

    [Fact]
    public void With_AddsTheCurve_AndLeavesTheOriginalUnchanged()
    {
        Pkcs11CurveCatalog extended = Pkcs11CurveCatalog.Default.With(Prime239v1);

        Assert.True(extended.TryGetByOid(Prime239v1Oid, out Pkcs11CurveInfo? byOid));
        Assert.True(extended.TryGetByName("prime239v1", out Pkcs11CurveInfo? byName));
        Assert.Same(Prime239v1, byOid);
        Assert.Same(Prime239v1, byName);
        Assert.Equal(Pkcs11CurveCatalog.Default.Curves.Count + 1, extended.Curves.Count);
        Assert.Equal(Prime239v1, extended.Curves[^1]);

        Assert.False(Pkcs11CurveCatalog.Default.TryGetByOid(Prime239v1Oid, out _));
    }

    // A catalog only grows: no entry can redescribe a built-in curve and weaken the checks that rely on it.
    [Fact]
    public void With_ExistingOid_Throws()
        => Assert.Throws<ArgumentException>("curve",
            () => Pkcs11CurveCatalog.Default.With(new Pkcs11CurveInfo("1.2.840.10045.3.1.7", "myP256", 384)));

    [Fact]
    public void With_ExistingName_Throws()
        => Assert.Throws<ArgumentException>("curve",
            () => Pkcs11CurveCatalog.Default.With(new Pkcs11CurveInfo("1.2.3.4", "nistP256", 256)));

    [Fact]
    public void With_Null_Throws()
        => Assert.Throws<ArgumentNullException>("curve", () => Pkcs11CurveCatalog.Default.With(null!));

    [Fact]
    public void TryGetByName_IsCaseSensitive()
        => Assert.False(Pkcs11CurveCatalog.Default.TryGetByName("NISTP256", out _));

    [Fact]
    public void Resolve_ListedOid_CarriesNameAndFieldSize()
    {
        Pkcs11CurveCatalog catalog = Pkcs11CurveCatalog.Default.With(Prime239v1);
        Pkcs11ECCurve bare = Pkcs11ECCurve.CreateFromValue(Prime239v1Oid);
        Assert.Null(bare.FieldSizeBits);

        Pkcs11ECCurve resolved = catalog.Resolve(bare);

        Assert.Equal(bare, resolved);
        Assert.Equal("prime239v1", resolved.FriendlyName);
        Assert.Equal(239, resolved.FieldSizeBits);
    }

    [Fact]
    public void Resolve_UnlistedOid_ReturnsTheCurveUnchanged()
    {
        Pkcs11ECCurve described = Pkcs11ECCurve.CreateFromValue("1.2.3.4", "mine", fieldSizeBits: 200);
        Pkcs11ECCurve resolved = Pkcs11CurveCatalog.Default.Resolve(described);
        Assert.Equal("mine", resolved.FriendlyName);
        Assert.Equal(200, resolved.FieldSizeBits);
    }

    [Fact]
    public void Resolve_Default_ReturnsDefault()
        => Assert.True(Pkcs11CurveCatalog.Default.Resolve(default).IsDefault);

    [Fact]
    public void Info_ToCurve_CarriesEverything()
    {
        Pkcs11ECCurve curve = Prime239v1.ToCurve();
        Assert.Equal(Prime239v1Oid, curve.Oid);
        Assert.Equal("prime239v1", curve.FriendlyName);
        Assert.Equal(239, curve.FieldSizeBits);
    }

    [Theory]
    [InlineData("not an oid")]
    [InlineData("")]
    public void Info_InvalidOid_Throws(string invalidOid)
        => Assert.Throws<ArgumentException>("oid", () => new Pkcs11CurveInfo(invalidOid, "x", 256));

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Info_BlankName_Throws(string blankName)
        => Assert.Throws<ArgumentException>("name", () => new Pkcs11CurveInfo("1.2.3.4", blankName, 256));

    [Theory]
    [InlineData(0)]
    [InlineData(-8)]
    public void Info_NonPositiveFieldSize_Throws(int bits)
        => Assert.Throws<ArgumentOutOfRangeException>("fieldSizeBits", () => new Pkcs11CurveInfo("1.2.3.4", "x", bits));

    [Fact]
    public void Info_WithoutOrderSize_HasTheFieldSize()
        => Assert.Equal(239, Prime239v1.OrderSizeBits);

    [Theory]
    [InlineData(160, 161)]
    [InlineData(256, 250)]
    [InlineData(int.MaxValue, int.MaxValue)]
    public void Info_OrderSize_IsKept(int fieldSizeBits, int orderSizeBits)
    {
        var info = new Pkcs11CurveInfo("1.2.3.4", "x", fieldSizeBits, orderSizeBits);
        Assert.Equal(fieldSizeBits, info.FieldSizeBits);
        Assert.Equal(orderSizeBits, info.OrderSizeBits);
    }

    // By Hasse's bound the order of a prime-order curve is less than twice the field's prime.
    [Theory]
    [InlineData(160, 0)]
    [InlineData(160, -1)]
    [InlineData(160, 162)]
    public void Info_OrderSizeOutOfRange_Throws(int fieldSizeBits, int orderSizeBits)
        => Assert.Throws<ArgumentOutOfRangeException>("orderSizeBits", () => new Pkcs11CurveInfo("1.2.3.4", "x", fieldSizeBits, orderSizeBits));

    [Fact]
    public void Info_NonPositiveFieldSizeWithOrderSize_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>("fieldSizeBits", () => new Pkcs11CurveInfo("1.2.3.4", "x", 0, 1));

    [Fact]
    public void Library_WithoutCatalogOption_UsesDefault()
    {
        using var library = new ManagedSoftToken().Load();
        Assert.Same(Pkcs11CurveCatalog.Default, library.CurveCatalog);
    }

    [Fact]
    public void Library_WithCatalogOption_UsesIt()
    {
        Pkcs11CurveCatalog catalog = Pkcs11CurveCatalog.Default.With(Prime239v1);
        using var library = new ManagedSoftToken().Load(new Pkcs11LibraryOptions { CurveCatalog = catalog });
        Assert.Same(catalog, library.CurveCatalog);
    }
}
