using System.Reflection;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Curves;

/// <summary>
/// Every <see cref="Pkcs11ECCurve.NamedCurves"/> property against the standard that defines its curve:
/// the OIDs are written out here rather than read from the library's constants, so a mistyped constant
/// fails. Properties are named by string and read through reflection, since naming an obsolete weak
/// curve in code, even in nameof, raises its diagnostic.
/// </summary>
public sealed class Pkcs11ECCurveNamedCurvesTests
{
    private static readonly PropertyInfo[] Properties =
        typeof(Pkcs11ECCurve.NamedCurves).GetProperties(BindingFlags.Public | BindingFlags.Static);

    private static Pkcs11ECCurve Read(string property)
        => (Pkcs11ECCurve)typeof(Pkcs11ECCurve.NamedCurves).GetProperty(property, BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!;

    [Theory]
    // FIPS 186-4 / SEC 2
    [InlineData("NistP192", "1.2.840.10045.3.1.1", "nistP192", 192)]
    [InlineData("NistP224", "1.3.132.0.33", "nistP224", 224)]
    [InlineData("NistP256", "1.2.840.10045.3.1.7", "nistP256", 256)]
    [InlineData("NistP384", "1.3.132.0.34", "nistP384", 384)]
    [InlineData("NistP521", "1.3.132.0.35", "nistP521", 521)]
    [InlineData("Secp160k1", "1.3.132.0.9", "secp160k1", 160)]
    [InlineData("Secp160r1", "1.3.132.0.8", "secp160r1", 160)]
    [InlineData("Secp160r2", "1.3.132.0.30", "secp160r2", 160)]
    [InlineData("Secp192k1", "1.3.132.0.31", "secp192k1", 192)]
    [InlineData("Secp224k1", "1.3.132.0.32", "secp224k1", 224)]
    [InlineData("Secp256k1", "1.3.132.0.10", "secp256k1", 256)]
    // RFC 5639
    [InlineData("BrainpoolP160r1", "1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1", 160)]
    [InlineData("BrainpoolP160t1", "1.3.36.3.3.2.8.1.1.2", "brainpoolP160t1", 160)]
    [InlineData("BrainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1", 192)]
    [InlineData("BrainpoolP192t1", "1.3.36.3.3.2.8.1.1.4", "brainpoolP192t1", 192)]
    [InlineData("BrainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1", 224)]
    [InlineData("BrainpoolP224t1", "1.3.36.3.3.2.8.1.1.6", "brainpoolP224t1", 224)]
    [InlineData("BrainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", 256)]
    [InlineData("BrainpoolP256t1", "1.3.36.3.3.2.8.1.1.8", "brainpoolP256t1", 256)]
    [InlineData("BrainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1", 320)]
    [InlineData("BrainpoolP320t1", "1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1", 320)]
    [InlineData("BrainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", 384)]
    [InlineData("BrainpoolP384t1", "1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1", 384)]
    [InlineData("BrainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", 512)]
    [InlineData("BrainpoolP512t1", "1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1", 512)]
    // GB/T 32918
    [InlineData("Sm2", "1.2.156.10197.1.301", "sm2", 256)]
    public void Property_IsTheStandardCurve(string property, string oid, string name, int fieldSizeBits)
    {
        Pkcs11ECCurve curve = Read(property);

        Assert.Equal(oid, curve.Oid);
        Assert.Equal(name, curve.FriendlyName);
        Assert.Equal(fieldSizeBits, curve.FieldSizeBits);
        Assert.Equal(Pkcs11ECCurve.CreateFromValue(oid), curve);
    }

    // The theory above covers each property it lists; this catches a curve added to one side only.
    [Fact]
    public void Properties_AreExactlyTheDefaultCatalog()
    {
        string?[] fromProperties = [.. Properties.Select(p => ((Pkcs11ECCurve)p.GetValue(null)!).Oid).Order(StringComparer.Ordinal)];
        string[] fromCatalog = [.. Pkcs11CurveCatalog.Default.Curves.Select(c => c.Oid).Order(StringComparer.Ordinal)];

        Assert.Equal(26, fromProperties.Length);
        Assert.Equal(fromCatalog, fromProperties);
    }
}
