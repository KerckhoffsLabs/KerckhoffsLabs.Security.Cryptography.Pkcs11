using System.Globalization;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SlotIdTests
{
    [Theory]
    [InlineData(0UL)]
    [InlineData(3UL)]
    [InlineData(ulong.MaxValue)]
    public void Constructor_RoundTripsValue(ulong raw)
        => Assert.Equal(raw, new SlotId(raw).Value);

    [Fact]
    public void Default_IsZero()
    {
        SlotId id = default;
        Assert.Equal(0UL, id.Value);
        Assert.Equal(new SlotId(0), id);
    }

    [Theory]
    [InlineData(0UL, "0")]
    [InlineData(3UL, "3")]
    [InlineData(ulong.MaxValue, "18446744073709551615")]
    public void ToString_IsPlainDecimal(ulong raw, string expected)
        => Assert.Equal(expected, new SlotId(raw).ToString());

    [Fact]
    public void ToString_IsCultureInvariant()
    {
        // The type formats with InvariantCulture; a culture with a different negative sign / digit
        // conventions must not leak into a slot id that vendor tooling displays as a plain number.
        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            Assert.Equal("1234567890", new SlotId(1234567890UL).ToString());
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void Equality_IsByValue()
    {
        var a = new SlotId(7);
        var b = new SlotId(7);
        var c = new SlotId(8);

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.False(a != b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());

        Assert.NotEqual(a, c);
        Assert.True(a != c);
    }
}
