// Licensed under the MIT License

using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using static KerckhoffsLabs.Runtime.InteropServices.Tests.PlatformLayout;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
{
    [Fact]
    public void Ctor_Empty()
    {
        NativeCULong value = new NativeCULong();
        Assert.Equal(0u, value.Value);
    }

    [Fact]
    public void Ctor_UInt()
    {
        NativeCULong value = new NativeCULong(42u);
        Assert.Equal(42u, value.Value);
    }

    [Fact]
    public void Ctor_NUInt()
    {
        NativeCULong value = new NativeCULong((nuint)42);
        Assert.Equal(42u, value.Value);
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.NativeIntConstructorCanOverflow))]
    public void Ctor_NUInt_OutOfRange()
    {
        Assert.Throws<OverflowException>(() => new NativeCULong(unchecked(((nuint)uint.MaxValue) + 1)));
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.NativeIntConstructorCannotOverflow))]
    public void Ctor_NUInt_LargeValue()
    {
        nuint largeValue = unchecked(((nuint)uint.MaxValue) + 1);
        NativeCULong value = new NativeCULong(largeValue);
        Assert.Equal(largeValue, value.Value);
    }

    public static IEnumerable<object[]> EqualsData()
    {
        yield return new object[] { new NativeCULong(789), new NativeCULong(789), true };
        yield return new object[] { new NativeCULong(789), new NativeCULong(0), false };
        yield return new object[] { new NativeCULong(0), new NativeCULong(0), true };
        yield return new object[] { new NativeCULong(789), null!, false };
        yield return new object[] { new NativeCULong(789), "789", false };
        yield return new object[] { new NativeCULong(789), 789u, false };
        yield return new object[] { NativeCULong.MaxValue, NativeCULong.MaxValue, true };
        // Note: cannot pair MaxValue with 0 here — the current EqualsTest also asserts
        // GetHashCode inequality for unequal values, and on 64-bit storage MaxValue
        // (0xFFFFFFFFFFFFFFFF) hashes to 0 (XOR-folded halves), colliding with 0's hash.
        yield return new object[] { NativeCULong.MaxValue, new NativeCULong(1), false };
    }

    [Theory]
    [MemberData(nameof(EqualsData))]
    public void EqualsTest(NativeCULong value, object obj, bool expected)
    {
        if (obj is NativeCULong other)
        {
            Assert.Equal(expected, value.Equals(other));
            Assert.Equal(expected, value.GetHashCode().Equals(other.GetHashCode()));
        }
        Assert.Equal(expected, value.Equals(obj));
    }

    [Theory]
    [InlineData(0, "0")]
    [InlineData(4567, "4567")]
    [InlineData(uint.MaxValue, "4294967295")]
    public void ToStringTest(uint value, string expected)
    {
        NativeCULong NativeCULong = new NativeCULong(value);

        Assert.Equal(expected, NativeCULong.ToString());
    }

    [Fact]
    public unsafe void Size()
    {
        int size = Has32BitStorage ? 4 : 8;
#pragma warning disable xUnit2000 // The value under test here is the sizeof expression
        Assert.Equal(size, sizeof(NativeCULong));
#pragma warning restore xUnit2000
        Assert.Equal(size, Marshal.SizeOf<NativeCULong>());
    }

    [Fact]
    public void MinValueTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NativeCULong.MinValue);
    }

    [Fact]
    public void MaxValueTest()
    {
        if (!OperatingSystem.IsWindows() && Environment.Is64BitProcess)
        {
            Assert.Equal(unchecked(new NativeCULong((nuint)0xFFFFFFFFFFFFFFFF)), NativeCULong.MaxValue);
        }
        else
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFF), NativeCULong.MaxValue);
        }
    }

    //
    // TryCreate (INumber<T> — deprecated in favor of CreateChecked; truncating semantics).
    //

    [Fact]
    public void TryCreate_FromInt_PositiveRoundTrips()
    {
        Assert.True(NativeCULong.TryCreate(42, out NativeCULong result));
        Assert.Equal(42u, (uint)result.Value);
    }

    [Fact]
    public void TryCreate_FromInt_NegativeWrapsToMaxValue()
    {
        // Truncating: -1 has every bit set in two's complement, which wraps to all-ones (MaxValue).
        Assert.True(NativeCULong.TryCreate(-1, out NativeCULong result));
        Assert.Equal(NativeCULong.MaxValue, result);
    }

    [Fact]
    public void TryCreate_FromULong_WithinUInt32Range_RoundTrips()
    {
        Assert.True(NativeCULong.TryCreate(0xFFFFFFFFUL, out NativeCULong result));
        Assert.Equal(0xFFFFFFFFu, (uint)result.Value);
    }
}
