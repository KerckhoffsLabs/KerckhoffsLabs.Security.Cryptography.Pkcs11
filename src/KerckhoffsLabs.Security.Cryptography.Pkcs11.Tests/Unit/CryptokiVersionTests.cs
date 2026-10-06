using System.Globalization;
using System.Text.RegularExpressions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// CK_VERSION's minor is the spec's "hundredths" portion, which is why the string rendering it used
// to reach the public API through was a trap: "3.02" and "3.2" are different modules that sort the
// wrong way as text, and no consumer could compare or order versions without parsing. These pin the
// comparable surface that replaced it, plus the spec-form rendering that stayed internal.
public sealed class CryptokiVersionTests
{
    private sealed class InfoFake : NotSupportedPkcs11Library
    {
        public byte Major = 3;
        public byte Minor = 2;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetInfo(ref CK_INFO info)
        {
            info.CryptokiVersion = new CK_VERSION { Major = Major, Minor = Minor };
            info.LibraryVersion = new CK_VERSION { Major = 1, Minor = 2 };
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void Versions_OrderByTheRawMinorField()
    {
        Version v301 = new CK_VERSION { Major = 3, Minor = 1 }.ToVersion();
        Version v302 = new CK_VERSION { Major = 3, Minor = 2 }.ToVersion();
        Version v310 = new CK_VERSION { Major = 3, Minor = 10 }.ToVersion();

        Assert.True(v301 < v302);
        Assert.True(v302 < v310);
        Assert.True(v310 < new CK_VERSION { Major = 4, Minor = 0 }.ToVersion());
    }

    // Once a module's minor passes 99 the spec-form rendering loses its fixed width, and ordinal text
    // order inverts against the real one. NSS softoken reports 3.125, so this is not hypothetical:
    // sorting the old string surface put it *below* a 3.99 module.
    [Fact]
    public void TextOrderOfTheSpecFormRendering_InvertsAbove99_ButVersionOrderDoesNot()
    {
        var v399 = new CK_VERSION { Major = 3, Minor = 99 };
        var v3125 = new CK_VERSION { Major = 3, Minor = 125 };

        Assert.True(v399.ToVersion() < v3125.ToVersion());
        Assert.True(string.CompareOrdinal(v399.ToString(), v3125.ToString()) > 0);
    }

    // The other half of the trap the string surface carried: a consumer who means "v3.2" cannot tell
    // from the rendering whether the module they want is the one printing "3.02" or "3.20".
    [Fact]
    public void SpecFormRendering_IsAmbiguousAboutWhichModuleIsMeant()
    {
        Assert.Equal("3.02", new CK_VERSION { Major = 3, Minor = 2 }.ToString());
        Assert.Equal("3.20", new CK_VERSION { Major = 3, Minor = 20 }.ToString());

        // Both satisfy a naive `>= "3.2"` string test, though only one is the later module.
        Assert.True(string.CompareOrdinal("3.20", "3.2") > 0);
        Assert.True(string.CompareOrdinal("3.02", "3.2") < 0);
    }

    [Theory]
    [InlineData(3, 0, "3.0")]      // minor 0 renders as a whole version
    [InlineData(3, 7, "3.07")]     // 1..99 zero-padded as hundredths
    [InlineData(3, 99, "3.99")]    // upper bound of the hundredths range
    [InlineData(3, 125, "3.125")]  // beyond it: NSS softoken really reports this
    public void SpecFormRendering_IsPreservedForDiagnostics(byte major, byte minor, string expected)
        => Assert.Equal(expected, new CK_VERSION { Major = major, Minor = minor }.ToString());

    [Fact]
    public void GetInfo_ExposesBothVersionsAsComparableValues()
    {
        using var fake = new InfoFake { Major = 3, Minor = 2 };
        using var library = new Pkcs11Library(fake);

        LibraryInfo info = library.GetInfo();

        Assert.Equal(CryptokiVersions.V3_2, info.CryptokiVersion);
        Assert.Equal(new Version(1, 2), info.LibraryVersion);
    }

    // A v3.2 module reports CK_VERSION {3, 2}, as the v3.2 header's CRYPTOKI_VERSION_MINOR defines it.
    [Theory]
    [InlineData(2, 40, true)]
    [InlineData(3, 0, true)]
    [InlineData(3, 1, true)]
    [InlineData(3, 2, true)]    // exactly the reported version
    [InlineData(3, 3, false)]   // one minor step past it
    [InlineData(3, 10, false)]  // the hundredths reading of "3.1", which no header uses
    [InlineData(4, 0, false)]
    public void SupportsCryptokiVersion_ComparesAgainstTheReportedVersion(int major, int minor, bool expected)
    {
        using var fake = new InfoFake { Major = 3, Minor = 2 };
        using var library = new Pkcs11Library(fake);

        Assert.Equal(expected, library.SupportsCryptokiVersion(new Version(major, minor)));
    }

    // A v2.40 module must not answer yes to a v3 question — the case the exception-driven
    // GetInterfaces() probe was previously the only way to decide.
    [Fact]
    public void SupportsCryptokiVersion_V240Module_RefusesV3()
    {
        using var fake = new InfoFake { Major = 2, Minor = 40 };
        using var library = new Pkcs11Library(fake);

        Assert.True(library.SupportsCryptokiVersion(CryptokiVersions.V2_40));
        Assert.False(library.SupportsCryptokiVersion(CryptokiVersions.V3_0));
    }

    [Fact]
    public void SupportsCryptokiVersion_Null_Throws()
    {
        using var fake = new InfoFake { Major = 3, Minor = 2 };
        using var library = new Pkcs11Library(fake);

        Assert.Throws<ArgumentNullException>("version", () => library.SupportsCryptokiVersion(null!));
    }

    // CK_VERSION has no build or revision, so the reported version never sets one, and Version orders
    // an unset build (-1) below 0: new Version(3, 2, 0) would compare above the {3, 2} a v3.2 module
    // reports and answer false. Refusing it beats that silent wrong answer.
    [Theory]
    [InlineData(3, 2, 0, -1)]
    [InlineData(3, 2, 0, 0)]
    public void SupportsCryptokiVersion_BuildOrRevision_IsRefused(int major, int minor, int build, int revision)
    {
        using var fake = new InfoFake { Major = 3, Minor = 2 };
        using var library = new Pkcs11Library(fake);
        Version version = revision < 0 ? new Version(major, minor, build) : new Version(major, minor, build, revision);

        Assert.Throws<ArgumentException>("version", () => library.SupportsCryptokiVersion(version));
        Assert.True(new Version(major, minor, build) > library.GetInfo().CryptokiVersion);
    }

    // The v3.2 header defines the version a v3.2 module reports; it is {3, 2}, not {3, 20}.
    [Fact]
    public void CryptokiVersions_V3_2_IsWhatTheV3_2HeaderDefines()
    {
        string path = Path.Join(AppContext.BaseDirectory, "pkcs11-v3.2", "pkcs11t.h");
        Assert.True(File.Exists(path), $"The vendored PKCS#11 v3.2 header is missing at {path}; initialize the vendor/pkcs11 submodule.");
        string header = File.ReadAllText(path);

        var defined = new Version(Define(header, "CRYPTOKI_VERSION_MAJOR"), Define(header, "CRYPTOKI_VERSION_MINOR"));

        Assert.Equal(CryptokiVersions.V3_2, defined);
        Assert.True(CryptokiVersions.V2_40 < CryptokiVersions.V3_0);
    }

    private static int Define(string header, string name)
        => int.Parse(Regex.Match(header, $@"#define\s+{name}\s+(\d+)").Groups[1].Value, CultureInfo.InvariantCulture);

    [Fact]
    public void SupportsCryptokiVersion_AfterDispose_Throws()
    {
        var fake = new InfoFake();
        var library = new Pkcs11Library(fake);
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.SupportsCryptokiVersion(CryptokiVersions.V3_0));
    }
}
