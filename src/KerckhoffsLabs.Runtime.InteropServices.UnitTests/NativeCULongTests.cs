// Licensed under the MIT License

using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using Xunit;

namespace KerckhoffsLabs.Runtime.InteropServices.UnitTests;

public class NativeCULongTests
{
    private static bool Has64BitStorage => !Has32BitStorage;
    private static bool Has32BitStorage => IntPtr.Size == 4 || OperatingSystem.IsWindows();
    private static bool NativeIntConstructorCanOverflow => IntPtr.Size != 4 && Has32BitStorage;
    private static bool NativeIntConstructorCannotOverflow => !NativeIntConstructorCanOverflow;

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

    [ConditionalFact(nameof(NativeIntConstructorCanOverflow))]
    public void Ctor_NUInt_OutOfRange()
    {
        Assert.Throws<OverflowException>(() => new NativeCULong(unchecked(((nuint)uint.MaxValue) + 1)));
    }

    [ConditionalFact(nameof(NativeIntConstructorCannotOverflow))]
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
        #pragma warning disable CS8625
        yield return new object[] { new NativeCULong(789), null, false };
        #pragma warning restore CS8625
        yield return new object[] { new NativeCULong(789), "789", false };
        yield return new object[] { new NativeCULong(789), 789u, false };
    }

    [Theory]
    [MemberData(nameof(EqualsData))]
    public void EqualsTest(NativeCULong NativeCULong, object obj, bool expected)
    {
        if (obj is NativeCULong NativeCULong2)
        {
            Assert.Equal(expected, NativeCULong.Equals(NativeCULong2));
            Assert.Equal(expected, NativeCULong.GetHashCode().Equals(NativeCULong2.GetHashCode()));
        }
        Assert.Equal(expected, NativeCULong.Equals(obj));
    }

    [Theory]
    [InlineData(0, "0")]
    [InlineData(4567, "4567")]
    [InlineData(uint.MaxValue, "4294967295")]
    public static void ToStringTest(uint value, string expected)
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
    public static void MinValueTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NativeCULong.MinValue);
    }

    [Fact]
    public static void MaxValueTest()
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
}