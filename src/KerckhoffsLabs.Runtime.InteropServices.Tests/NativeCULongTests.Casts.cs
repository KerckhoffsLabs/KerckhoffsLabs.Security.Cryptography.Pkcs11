// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
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

    [Fact]
    public void Cast_FromNegativeLong_Throws_UnderCheckedContext()
    {
        Assert.Throws<System.OverflowException>(() =>
        {
            long negative = -1L;
            NativeCULong _ = (NativeCULong)negative;
        });
    }

    [Fact]
    public void Cast_FromNegativeLong_Wraps_InsideUncheckedBlock()
    {
        unchecked
        {
            long negative = -1L;
            NativeCULong c = (NativeCULong)negative;
            // -1L wraps to all-bits-set in the storage width — matches MaxValue
            // on both 32-bit and 64-bit NativeCULong storage.
            Assert.Equal(NativeCULong.MaxValue, c);
        }
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has64BitStorage))]
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

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has64BitStorage))]
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

    // ---- Plain (non-checked) op_Explicit coverage ------------------------------
    // The project-wide CheckForOverflowUnderflow=true routes bare casts to the
    // `operator checked` overload, leaving the plain overloads dead. The
    // `unchecked { ... }` block below forces the plain path.

    [Fact]
    public void Cast_FromULong_Plain_WithinRange_InsideUncheckedBlock()
    {
        unchecked
        {
            NativeCULong c = (NativeCULong)(ulong)42UL;
            Assert.Equal(42u, (uint)c.Value);
        }
    }

    [Fact]
    public void Cast_ToULong_Plain_InsideUncheckedBlock()
    {
        // NativeCULong → ulong is always exact (ulong holds any NativeCULong value),
        // so plain and checked produce identical results; this just exercises the
        // plain operator path that the default-checked context bypasses.
        NativeCULong c = new NativeCULong(42u);
        unchecked
        {
            ulong v = (ulong)c;
            Assert.Equal(42UL, v);
        }
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has32BitStorage))]
    public void Cast_FromULong_Plain_HighBitsTruncate_On32BitStorage()
    {
        unchecked
        {
            // 0x1_0000_0000 has the low 32 bits zero; on 32-bit storage the plain
            // operator truncates without throwing (checked variant would throw).
            ulong tooBig = (ulong)uint.MaxValue + 1UL;
            NativeCULong c = (NativeCULong)tooBig;
            Assert.Equal(0u, (uint)c.Value);
        }
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has64BitStorage))]
    public void Cast_ToUInt_Plain_TruncatesOn64BitStorage_InsideUncheckedBlock()
    {
        NativeCULong tooBig = new NativeCULong(unchecked((nuint)((ulong)uint.MaxValue + 1UL)));
        unchecked
        {
            uint wrapped = (uint)tooBig;
            // 0x1_0000_0000 truncated to uint = 0.
            Assert.Equal(0u, wrapped);
        }
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has64BitStorage))]
    public void Cast_ToLong_Plain_WrapsOn64BitStorage_InsideUncheckedBlock()
    {
        // Value > long.MaxValue: top bit set in 64-bit storage; plain cast reinterprets as negative.
        NativeCULong huge = new NativeCULong(unchecked((nuint)0x8000_0000_0000_0000UL));
        unchecked
        {
            long wrapped = (long)huge;
            Assert.Equal(long.MinValue, wrapped);
        }
    }
}
