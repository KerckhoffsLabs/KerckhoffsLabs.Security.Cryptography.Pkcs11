using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

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
    public void Info_InvalidOid_Throws(string oid)
        => Assert.Throws<ArgumentException>("oid", () => new Pkcs11CurveInfo(oid, "x", 256));

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Info_BlankName_Throws(string name)
        => Assert.Throws<ArgumentException>("name", () => new Pkcs11CurveInfo("1.2.3.4", name, 256));

    [Theory]
    [InlineData(0)]
    [InlineData(-8)]
    public void Info_NonPositiveFieldSize_Throws(int bits)
        => Assert.Throws<ArgumentOutOfRangeException>("fieldSizeBits", () => new Pkcs11CurveInfo("1.2.3.4", "x", bits));

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
