namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SessionIdTests
{
    // SessionId's constructor is internal (module-produced handles only); reachable here via
    // InternalsVisibleTo.

    [Theory]
    [InlineData(0UL)]
    [InlineData(0x1FUL)]
    [InlineData(ulong.MaxValue)]
    public void Constructor_RoundTripsValue(ulong raw)
        => Assert.Equal(raw, new SessionId(raw).Value);

    [Fact]
    public void Default_IsZero()
    {
        SessionId id = default;
        Assert.Equal(0UL, id.Value);
        Assert.Equal(new SessionId(0), id);
    }

    [Theory]
    [InlineData(0UL, "0x0")]
    [InlineData(0x1FUL, "0x1F")]                       // uppercase, no leading zeros
    [InlineData(0xDEADBEEFUL, "0xDEADBEEF")]
    [InlineData(ulong.MaxValue, "0xFFFFFFFFFFFFFFFF")]
    public void ToString_IsUppercaseHexWith0xPrefix(ulong raw, string expected)
        => Assert.Equal(expected, new SessionId(raw).ToString());

    [Fact]
    public void Equality_IsByValue()
    {
        var a = new SessionId(0x42);
        var b = new SessionId(0x42);
        var c = new SessionId(0x43);

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.False(a != b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());

        Assert.NotEqual(a, c);
        Assert.True(a != c);
    }
}
