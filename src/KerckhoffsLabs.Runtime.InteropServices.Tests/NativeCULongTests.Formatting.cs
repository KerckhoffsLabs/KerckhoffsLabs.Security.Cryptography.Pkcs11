// Licensed under the MIT License

using System.Globalization;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
{
    //
    // ToString(format) / ToString(provider)
    //

    [Theory]
    [InlineData("D",  "42")]
    [InlineData("X",  "2A")]
    [InlineData("X4", "002A")]
    [InlineData("D5", "00042")]
    public void ToString_Format_FormatsValue(string format, string expected)
    {
        NativeCULong v = new NativeCULong(42u);
        Assert.Equal(expected, v.ToString(format));
    }

    [Fact]
    public void ToString_Provider_UsesProvider()
    {
        // Default integer ToString does not interpolate culture-specific separators,
        // but the (IFormatProvider) overload still dispatches through the BCL.
        NativeCULong v = new NativeCULong(1234567u);
        Assert.Equal("1234567", v.ToString(CultureInfo.InvariantCulture));
    }

    //
    // TryFormat (ISpanFormattable)
    //

    [Fact]
    public void TryFormat_FitsDestination_WritesAndReturnsTrue()
    {
        Span<char> destination = stackalloc char[16];
        NativeCULong v = new NativeCULong(42u);
        Assert.True(v.TryFormat(destination, out int written, default, CultureInfo.InvariantCulture));
        Assert.Equal(2, written);
        Assert.Equal("42", destination[..written].ToString());
    }

    [Fact]
    public void TryFormat_HexFormat_WritesHex()
    {
        Span<char> destination = stackalloc char[16];
        NativeCULong v = new NativeCULong(0xCAFEu);
        Assert.True(v.TryFormat(destination, out int written, "X", CultureInfo.InvariantCulture));
        Assert.Equal(4, written);
        Assert.Equal("CAFE", destination[..written].ToString());
    }

    [Fact]
    public void TryFormat_DestinationTooSmall_ReturnsFalse()
    {
        Span<char> destination = stackalloc char[1]; // 1 char is too small for "42"
        NativeCULong v = new NativeCULong(42u);
        Assert.False(v.TryFormat(destination, out int written, default, CultureInfo.InvariantCulture));
        Assert.Equal(0, written);
    }

    //
    // Parse / TryParse — IParsable<TSelf>
    //

    [Theory]
    [InlineData("0",          0u)]
    [InlineData("42",         42u)]
    [InlineData("4294967295", uint.MaxValue)]
    public void Parse_String_DefaultStyle_RoundTrips(string input, uint expected)
    {
        NativeCULong v = NativeCULong.Parse(input, CultureInfo.InvariantCulture);
        Assert.Equal(expected, (uint)v.Value);
    }

    [Theory]
    [InlineData("FF",       0xFFu)]
    [InlineData("CAFE",     0xCAFEu)]
    [InlineData("ffffffff", uint.MaxValue)]
    public void Parse_String_HexStyle_RoundTrips(string input, uint expected)
    {
        NativeCULong v = NativeCULong.Parse(input, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Assert.Equal(expected, (uint)v.Value);
    }

    [Fact]
    public void Parse_InvalidInput_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => NativeCULong.Parse("not-a-number", CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData("0",  0u)]
    [InlineData("42", 42u)]
    public void TryParse_String_DefaultStyle_Success(string input, uint expected)
    {
        Assert.True(NativeCULong.TryParse(input, CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(expected, (uint)v.Value);
    }

    [Theory]
    [InlineData("FF",   0xFFu)]
    [InlineData("CAFE", 0xCAFEu)]
    public void TryParse_String_HexStyle_Success(string input, uint expected)
    {
        Assert.True(NativeCULong.TryParse(input, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(expected, (uint)v.Value);
    }

    [Fact]
    public void TryParse_InvalidInput_ReturnsFalseAndDefault()
    {
        Assert.False(NativeCULong.TryParse("invalid", CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(default, v);
    }

    [Fact]
    public void TryParse_NullString_ReturnsFalse()
    {
        Assert.False(NativeCULong.TryParse((string?)null, CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(default, v);
    }

    //
    // Parse / TryParse — ISpanParsable<TSelf>
    //

    [Theory]
    [InlineData("0",          0u)]
    [InlineData("42",         42u)]
    [InlineData("4294967295", uint.MaxValue)]
    public void Parse_Span_DefaultStyle_RoundTrips(string input, uint expected)
    {
        NativeCULong v = NativeCULong.Parse(input.AsSpan(), CultureInfo.InvariantCulture);
        Assert.Equal(expected, (uint)v.Value);
    }

    [Fact]
    public void Parse_Span_HexStyle_RoundTrips()
    {
        NativeCULong v = NativeCULong.Parse("CAFE".AsSpan(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Assert.Equal(0xCAFEu, (uint)v.Value);
    }

    [Fact]
    public void TryParse_Span_DefaultStyle_Success()
    {
        Assert.True(NativeCULong.TryParse("123".AsSpan(), CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(123u, (uint)v.Value);
    }

    [Fact]
    public void TryParse_Span_HexStyle_Success()
    {
        Assert.True(NativeCULong.TryParse("DEAD".AsSpan(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(0xDEADu, (uint)v.Value);
    }

    [Fact]
    public void TryParse_Span_InvalidInput_ReturnsFalseAndDefault()
    {
        Assert.False(NativeCULong.TryParse("invalid".AsSpan(), CultureInfo.InvariantCulture, out NativeCULong v));
        Assert.Equal(default, v);
    }
}
