// Licensed under the MIT License
// Smoke coverage for INumberBase<NativeCULong>.Create{Checked,Saturating,Truncating}.
// NativeCULong's storage width varies by platform (32-bit on Windows / 32-bit Linux,
// 64-bit on 64-bit Unix LP64), so these conversions are the most platform-sensitive
// surface of the type.

using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
{
    //
    // CreateChecked: throws on overflow.
    //

    [Fact]
    public void CreateChecked_FromByte_AlwaysFits()
    {
        Assert.Equal(new NativeCULong(0x00), NumberBaseHelper<NativeCULong>.CreateChecked<byte>(0x00));
        Assert.Equal(new NativeCULong(0xFF), NumberBaseHelper<NativeCULong>.CreateChecked<byte>(0xFF));
    }

    [Fact]
    public void CreateChecked_FromInt_PositiveRoundTrips()
    {
        Assert.Equal(new NativeCULong(0x00000000), NumberBaseHelper<NativeCULong>.CreateChecked<int>(0));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), NumberBaseHelper<NativeCULong>.CreateChecked<int>(int.MaxValue));
    }

    [Fact]
    public void CreateChecked_FromInt_NegativeThrows()
    {
        Assert.Throws<OverflowException>(() => NumberBaseHelper<NativeCULong>.CreateChecked<int>(-1));
    }

    [Fact]
    public void CreateChecked_FromLong_WithinUInt32Range()
    {
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberBaseHelper<NativeCULong>.CreateChecked<long>(0xFFFFFFFFL));
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has32BitStorage))]
    public void CreateChecked_FromLong_ExceedingUInt32MaxThrowsOn32BitStorage()
    {
        Assert.Throws<OverflowException>(() => NumberBaseHelper<NativeCULong>.CreateChecked<long>(0x1_0000_0000L));
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has64BitStorage))]
    public void CreateChecked_FromLong_ExceedingUInt32MaxFitsOn64BitStorage()
    {
#pragma warning disable CS8778 // intentional 64-bit-storage literal; gated at runtime by Has64BitStorage
        Assert.Equal(new NativeCULong((nuint)0x1_0000_0000UL), NumberBaseHelper<NativeCULong>.CreateChecked<long>(0x1_0000_0000L));
#pragma warning restore CS8778
    }

    [Fact]
    public void CreateChecked_FromLong_NegativeThrows()
    {
        Assert.Throws<OverflowException>(() => NumberBaseHelper<NativeCULong>.CreateChecked<long>(-1L));
    }

    [Fact]
    public void CreateChecked_FromNUint_Identity()
    {
        nuint v = 42;
        Assert.Equal(new NativeCULong(v), NumberBaseHelper<NativeCULong>.CreateChecked<nuint>(v));
    }

    //
    // CreateSaturating: clamps to bounds on overflow.
    //

    [Fact]
    public void CreateSaturating_FromInt_NegativeSaturatesToMin()
    {
        Assert.Equal(NativeCULong.MinValue, NumberBaseHelper<NativeCULong>.CreateSaturating<int>(-1));
    }

    [Fact]
    public void CreateSaturating_FromInt_PositiveRoundTrips()
    {
        Assert.Equal(new NativeCULong(0x7FFFFFFF), NumberBaseHelper<NativeCULong>.CreateSaturating<int>(int.MaxValue));
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has32BitStorage))]
    public void CreateSaturating_FromLong_ExceedingUInt32MaxSaturatesOn32BitStorage()
    {
        Assert.Equal(NativeCULong.MaxValue, NumberBaseHelper<NativeCULong>.CreateSaturating<long>(0x1_0000_0000L));
    }

    [Fact]
    public void CreateSaturating_FromLong_NegativeSaturatesToMin()
    {
        Assert.Equal(NativeCULong.MinValue, NumberBaseHelper<NativeCULong>.CreateSaturating<long>(-1L));
    }

    //
    // CreateTruncating: wraps on overflow (low-order bits preserved).
    //

    [Fact]
    public void CreateTruncating_FromInt_NegativeWraps()
    {
        // -1 has every bit set in two's complement; truncating to NativeCULong's
        // storage width yields the all-ones value, which is MaxValue.
        Assert.Equal(NativeCULong.MaxValue, NumberBaseHelper<NativeCULong>.CreateTruncating<int>(-1));
    }

    [ConditionalFact(typeof(PlatformLayout), nameof(PlatformLayout.Has32BitStorage))]
    public void CreateTruncating_FromLong_HighBitsDroppedOn32BitStorage()
    {
        Assert.Equal(new NativeCULong(0x00000001), NumberBaseHelper<NativeCULong>.CreateTruncating<long>(0x1_0000_0001L));
    }

    //
    // CreateChecked (reverse direction): NativeCULong -> TOther.
    //

    [Fact]
    public void CreateChecked_ToByte_FitsRoundTrips()
    {
        Assert.Equal((byte)0xFF, NumberBaseHelper<byte>.CreateChecked<NativeCULong>(new NativeCULong(0xFF)));
    }

    [Fact]
    public void CreateChecked_ToByte_ExceedingThrows()
    {
        Assert.Throws<OverflowException>(() => NumberBaseHelper<byte>.CreateChecked<NativeCULong>(new NativeCULong(0x100)));
    }

    [Fact]
    public void CreateChecked_ToInt_PositiveRoundTrips()
    {
        Assert.Equal(0x7FFFFFFF, NumberBaseHelper<int>.CreateChecked<NativeCULong>(new NativeCULong(0x7FFFFFFF)));
    }

    [Fact]
    public void CreateChecked_ToInt_LargeValueThrows()
    {
        // Value exceeding int.MaxValue must throw on every platform (uint can hold
        // 0x80000000 even on 32-bit storage).
        NativeCULong tooBig = new NativeCULong(0x80000000u);
        Assert.Throws<OverflowException>(() => NumberBaseHelper<int>.CreateChecked<NativeCULong>(tooBig));
    }

    [Fact]
    public void CreateSaturating_ToByte_ExceedingSaturatesToFF()
    {
        Assert.Equal((byte)0xFF, NumberBaseHelper<byte>.CreateSaturating<NativeCULong>(new NativeCULong(0x100)));
    }

    [Fact]
    public void CreateSaturating_ToInt_LargeValueSaturatesToMax()
    {
        Assert.Equal(int.MaxValue, NumberBaseHelper<int>.CreateSaturating<NativeCULong>(new NativeCULong(0x80000000u)));
    }

    [Fact]
    public void CreateTruncating_ToByte_WrapsToLowOctet()
    {
        Assert.Equal((byte)0x42, NumberBaseHelper<byte>.CreateTruncating<NativeCULong>(new NativeCULong(0x12345642)));
    }

    [Fact]
    public void CreateTruncating_ToInt_LargeValueWrapsToLow32Bits()
    {
        // 0x80000000 truncated and reinterpreted as int = int.MinValue.
        Assert.Equal(int.MinValue, NumberBaseHelper<int>.CreateTruncating<NativeCULong>(new NativeCULong(0x80000000u)));
    }
}
