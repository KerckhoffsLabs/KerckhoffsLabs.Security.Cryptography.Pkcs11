// Licensed under the MIT License

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
{
    //
    // IComparable<NativeCULong>.CompareTo(NativeCULong)
    //

    [Fact]
    public void CompareTo_Equal_ReturnsZero()
    {
        Assert.Equal(0, new NativeCULong(42u).CompareTo(new NativeCULong(42u)));
    }

    [Fact]
    public void CompareTo_LessThan_ReturnsNegative()
    {
        Assert.InRange(new NativeCULong(1u).CompareTo(new NativeCULong(2u)), int.MinValue, -1);
    }

    [Fact]
    public void CompareTo_GreaterThan_ReturnsPositive()
    {
        Assert.InRange(new NativeCULong(2u).CompareTo(new NativeCULong(1u)), 1, int.MaxValue);
    }

    //
    // IComparable.CompareTo(object?)
    //

    [Fact]
    public void CompareTo_Object_SameType_DelegatesToTyped()
    {
        NativeCULong a = new NativeCULong(42u);
        Assert.Equal(0, a.CompareTo((object)new NativeCULong(42u)));
        Assert.InRange(a.CompareTo((object)new NativeCULong(43u)), int.MinValue, -1);
        Assert.InRange(a.CompareTo((object)new NativeCULong(41u)), 1, int.MaxValue);
    }

    [Fact]
    public void CompareTo_Object_Null_ReturnsPositive()
    {
        // BCL convention: null is treated as "less than" any non-null value.
        Assert.InRange(new NativeCULong(42u).CompareTo((object?)null), 1, int.MaxValue);
    }

    [Fact]
    public void CompareTo_Object_WrongType_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new NativeCULong(42u).CompareTo((object)42));
    }
}
