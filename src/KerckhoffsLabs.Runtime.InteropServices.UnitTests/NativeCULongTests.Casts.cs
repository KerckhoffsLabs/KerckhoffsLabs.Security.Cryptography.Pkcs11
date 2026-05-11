// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using Xunit;

namespace KerckhoffsLabs.Runtime.InteropServices.UnitTests;

public class NativeCULongCastTests
{
    // ---- Primitive -> NativeCULong (round-trip via Value) -------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void Cast_FromInt_RoundTrips(int value)
    {
        NativeCULong c = (NativeCULong)value;
        Assert.Equal((uint)value, (uint)c.Value);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(uint.MaxValue)]
    public void Cast_FromUInt_RoundTrips(uint value)
    {
        NativeCULong c = (NativeCULong)value;
        Assert.Equal(value, (uint)c.Value);
    }

    [Fact]
    public void Cast_FromLong_RoundTrips_ZeroAndPositive()
    {
        Assert.Equal(0u, (uint)((NativeCULong)0L).Value);
        Assert.Equal(42u, (uint)((NativeCULong)42L).Value);
    }

    [Fact]
    public void Cast_FromULong_RoundTrips_WithinRange()
    {
        Assert.Equal(0u, (uint)((NativeCULong)0UL).Value);
        Assert.Equal(uint.MaxValue, (uint)((NativeCULong)(ulong)uint.MaxValue).Value);
    }

    [Fact]
    public void Cast_FromNUint_Identity()
    {
        nuint n = 12345;
        NativeCULong c = (NativeCULong)n;
        Assert.Equal(n, c.Value);
    }

    // ---- NativeCULong -> primitive ------------------------------------------

    [Fact]
    public void Cast_ToInt_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42, (int)c);
    }

    [Fact]
    public void Cast_ToUInt_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42u, (uint)c);
    }

    [Fact]
    public void Cast_ToLong_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42L, (long)c);
    }

    [Fact]
    public void Cast_ToULong_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal(42UL, (ulong)c);
    }

    [Fact]
    public void Cast_ToNUint_PreservesValue()
    {
        NativeCULong c = new NativeCULong(42u);
        Assert.Equal((nuint)42, (nuint)c);
    }

    // ---- Overflow: with project-wide CheckForOverflowUnderflow=true,
    //               a negative int cast to NativeCULong throws.
    //               Inside explicit `unchecked`, it wraps. -------------------

    [Fact]
    public void Cast_FromNegativeInt_Throws_UnderCheckedContext()
    {
        Assert.Throws<System.OverflowException>(() =>
        {
            int negative = -1;
            NativeCULong _ = (NativeCULong)negative;
        });
    }

    [Fact]
    public void Cast_FromNegativeInt_Wraps_InsideUncheckedBlock()
    {
        unchecked
        {
            int negative = -1;
            NativeCULong c = (NativeCULong)negative;
            Assert.Equal(uint.MaxValue, (uint)c.Value);
        }
    }

    private static bool Has64BitStorage => !Has32BitStorage;
    private static bool Has32BitStorage => IntPtr.Size == 4 || OperatingSystem.IsWindows();

    [ConditionalFact(nameof(Has64BitStorage))]
    public void Cast_ToInt_ThrowsOnUnix64WhenValueExceedsIntRange()
    {
        // On 64-bit Unix, NativeCULong is backed by nuint (64-bit), so it can hold
        // values larger than int.MaxValue. The checked outgoing operator must throw.
        NativeCULong tooBig = new NativeCULong((nuint)((long)int.MaxValue + 1));
        Assert.Throws<System.OverflowException>(() =>
        {
            int _ = (int)tooBig;
        });
    }

    [ConditionalFact(nameof(Has64BitStorage))]
    public void Cast_ToInt_WrapsOnUnix64InUncheckedBlock()
    {
        NativeCULong tooBig = new NativeCULong((nuint)((long)int.MaxValue + 1));
        unchecked
        {
            int wrapped = (int)tooBig;
            // (int)((long)int.MaxValue + 1) underflows to int.MinValue
            Assert.Equal(int.MinValue, wrapped);
        }
    }
}
