using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <see cref="CkULong.From"/> narrows a caller's <see cref="ulong"/> to <c>CK_ULONG</c>, which is 32 bits on
/// Windows and on 32-bit Unix and 64 bits elsewhere. A value that does not fit is refused, naming the
/// argument, rather than truncated into a different value the token would accept.
/// </summary>
/// <remarks>
/// The tests of <see cref="CkULong.From"/> expect what this platform should do, derived from the platform
/// rather than from <c>NativeCULong</c>, so they run everywhere and also catch a wrong width. The tests of
/// <see cref="CkULong.ThrowIfWider"/> pass the width explicitly, so both widths are checked on any platform.
/// </remarks>
public sealed class CkULongTests
{
    private const string Argument = "mechanismType";

    private static readonly bool CkULongIs32Bits = OperatingSystem.IsWindows() || IntPtr.Size == sizeof(uint);

    [Theory]
    [InlineData(0UL)]
    [InlineData(0x8000_0001UL)]
    [InlineData((ulong)uint.MaxValue)]
    public void From_AValueThatFitsEverywhere_RoundTrips(ulong value)
        => Assert.Equal(value, (ulong)CkULong.From(value, Argument));

    [Theory]
    [InlineData((ulong)uint.MaxValue + 1)]
    [InlineData(ulong.MaxValue)]
    public void From_AValueWiderThan32Bits_RoundTripsOnlyWhereCkULongIs64Bits(ulong value)
    {
        if (CkULongIs32Bits)
            Assert.Throws<ArgumentOutOfRangeException>(Argument, () => CkULong.From(value, Argument));
        else
            Assert.Equal(value, (ulong)CkULong.From(value, Argument));
    }

    [Theory]
    [InlineData(4, (ulong)uint.MaxValue)]
    [InlineData(8, (ulong)uint.MaxValue + 1)]
    [InlineData(8, ulong.MaxValue)]
    public void ThrowIfWider_AcceptsEveryValueTheWidthHolds(int ckULongBytes, ulong value)
        => Assert.Null(Record.Exception(() => CkULong.ThrowIfWider(value, Argument, ckULongBytes)));

    [Theory]
    [InlineData((ulong)uint.MaxValue + 1)]
    [InlineData(ulong.MaxValue)]
    public void ThrowIfWider_RefusesAValueA32BitCkULongCannotHold(ulong value)
        => Assert.Throws<ArgumentOutOfRangeException>(Argument, () => CkULong.ThrowIfWider(value, Argument, sizeof(uint)));

    // The refusal tells the caller which argument, which value and why, so the error can be acted on.
    [Fact]
    public void ThrowIfWider_Refusal_NamesTheArgumentTheValueAndTheWidth()
    {
        const ulong value = 0x1_0000_0002UL;

        var e = Assert.Throws<ArgumentOutOfRangeException>(Argument, () => CkULong.ThrowIfWider(value, Argument, sizeof(uint)));

        Assert.Equal(value, e.ActualValue);
        Assert.Contains("0x100000002", e.Message, StringComparison.Ordinal);
        Assert.Contains("32 bits", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ThrowIfWider_WithoutAnArgumentName_StillRefuses()
    {
        var e = Assert.Throws<ArgumentOutOfRangeException>(() => CkULong.ThrowIfWider(ulong.MaxValue, paramName: null, sizeof(uint)));

        Assert.Null(e.ParamName);
    }
}
