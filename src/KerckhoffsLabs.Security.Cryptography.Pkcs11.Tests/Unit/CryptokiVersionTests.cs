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
        public byte Minor = 20;

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
        using var fake = new InfoFake { Major = 3, Minor = 20 };
        using var library = new Pkcs11Library(fake);

        LibraryInfo info = library.GetInfo();

        Assert.Equal(new Version(3, 20), info.CryptokiVersion);
        Assert.Equal(new Version(1, 2), info.LibraryVersion);
    }

    [Theory]
    [InlineData(2, 40, true)]
    [InlineData(3, 0, true)]
    [InlineData(3, 20, true)]   // exactly the reported version
    [InlineData(3, 21, false)]  // one minor step past it
    [InlineData(4, 0, false)]
    public void SupportsCryptokiVersion_ComparesAgainstTheReportedVersion(int major, int minor, bool expected)
    {
        using var fake = new InfoFake { Major = 3, Minor = 20 };
        using var library = new Pkcs11Library(fake);

        Assert.Equal(expected, library.SupportsCryptokiVersion(major, minor));
    }

    // A v2.40 module must not answer yes to a v3 question — the case the exception-driven
    // GetInterfaces() probe was previously the only way to decide.
    [Fact]
    public void SupportsCryptokiVersion_V240Module_RefusesV3()
    {
        using var fake = new InfoFake { Major = 2, Minor = 40 };
        using var library = new Pkcs11Library(fake);

        Assert.True(library.SupportsCryptokiVersion(2, 40));
        Assert.False(library.SupportsCryptokiVersion(3, 0));
    }

    [Fact]
    public void SupportsCryptokiVersion_AfterDispose_Throws()
    {
        var fake = new InfoFake();
        var library = new Pkcs11Library(fake);
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.SupportsCryptokiVersion(3, 0));
    }
}
