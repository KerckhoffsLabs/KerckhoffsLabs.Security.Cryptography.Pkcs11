using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Decode coverage for the fixed-width, space-padded PKCS#11 string fields (the <c>CkChar16</c> /
/// <c>CkChar32</c> inline buffers behind <c>CK_INFO</c>, <c>CK_TOKEN_INFO</c>, …). The wrappers
/// (<see cref="LibraryInfo"/>, <see cref="TokenInfo"/>) decode them as UTF-8 and <c>TrimEnd()</c> the
/// PKCS#11 space padding; these tests pin the trim/preserve/empty/exact-fit behavior without a token.
/// </summary>
public sealed class FixedWidthStringTests
{
    private static LibraryInfo MakeLibraryInfo(string manufacturer, string description)
    {
        var info = new CK_INFO
        {
            CryptokiVersion = new CK_VERSION { Major = 3, Minor = 2 },
            LibraryVersion = new CK_VERSION { Major = 1, Minor = 0 },
        };
        NativeTestStructs.FillPadded(info.ManufacturerId, manufacturer);
        NativeTestStructs.FillPadded(info.LibraryDescription, description);
        return new LibraryInfo(info);
    }

    [Fact]
    public void TrailingSpacePadding_IsTrimmed()
    {
        var info = MakeLibraryInfo("ACME Corp", "PKCS11 library");
        Assert.Equal("ACME Corp", info.ManufacturerId);
        Assert.Equal("PKCS11 library", info.LibraryDescription);
    }

    [Fact]
    public void InternalSpaces_ArePreserved()
    {
        // Only trailing padding is stripped; interior spaces survive.
        var info = MakeLibraryInfo("a b  c", "x");
        Assert.Equal("a b  c", info.ManufacturerId);
    }

    [Fact]
    public void AllPadding_DecodesToEmptyString()
    {
        var info = MakeLibraryInfo("", "");
        Assert.Equal("", info.ManufacturerId);
        Assert.Equal("", info.LibraryDescription);
    }

    [Fact]
    public void ExactWidth_IsNotTruncated()
    {
        // 32 bytes exactly fill CkChar32 — there is no trailing padding to trim.
        string full = new('X', 32);
        var info = MakeLibraryInfo(full, "");
        Assert.Equal(full, info.ManufacturerId);
    }

    [Fact]
    public void TokenInfo_DecodesLabelAndModel_AcrossBufferWidths()
    {
        // Label is a 32-byte buffer, Model a 16-byte buffer — exercises both inline widths.
        var ck = new CK_TOKEN_INFO();
        NativeTestStructs.FillPadded(ck.Label, "my-token");
        NativeTestStructs.FillPadded(ck.Model, "model-7");

        var token = new TokenInfo((NativeCULong)0, ck);
        Assert.Equal("my-token", token.Label);
        Assert.Equal("model-7", token.Model);
    }
}
