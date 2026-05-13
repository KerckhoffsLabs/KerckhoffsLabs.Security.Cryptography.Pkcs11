// Licensed under the MIT License
// Adapted from dotnet/runtime UInt32Tests.GenericMath.cs for NativeCULong

using System.Numerics;
using static KerckhoffsLabs.Runtime.InteropServices.Tests.PlatformLayout;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public partial class NativeCULongTests
{
    //
    // IAdditionOperators
    //

    [Fact]
    public void op_AdditionTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000002), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000000), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000001), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0x80000000), new NativeCULong(1)));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0x00000000), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
        }
#if !WINDOWS
        else
        {
#pragma warning disable CS8778 // intentional 64-bit-storage literal; gated at runtime by Has32BitStorage
            Assert.Equal(new NativeCULong((nuint)0x0000000100000000UL), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Addition(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
#pragma warning restore CS8778
        }
#endif
    }

    [Fact]
    public void op_CheckedAdditionTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedAddition(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000002), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedAddition(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000000), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedAddition(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000001), AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedAddition(new NativeCULong(0x80000000), new NativeCULong(1)));

        if (Has32BitStorage)
        {
            Assert.Throws<OverflowException>(() => AdditionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedAddition(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
        }
    }

    //
    // IAdditiveIdentity
    //

    [Fact]
    public void AdditiveIdentityTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), AdditiveIdentityHelper<NativeCULong, NativeCULong>.AdditiveIdentity);
    }

    //
    // IBinaryInteger
    //

    [Fact]
    public void DivRemTest()
    {
        Assert.Equal((new NativeCULong(0x00000000), new NativeCULong(0x00000000)), BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal((new NativeCULong(0x00000000), new NativeCULong(0x00000001)), BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0x00000001), new NativeCULong(2)));
        Assert.Equal((new NativeCULong(0x3FFFFFFF), new NativeCULong(0x00000001)), BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
        Assert.Equal((new NativeCULong(0x40000000), new NativeCULong(0x00000000)), BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0x80000000), new NativeCULong(2)));
        Assert.Equal((new NativeCULong(0x7FFFFFFF), new NativeCULong(0x00000001)), BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));

        Assert.Throws<DivideByZeroException>(() => BinaryIntegerHelper<NativeCULong>.DivRem(new NativeCULong(0x00000001), new NativeCULong(0)));
    }

    [Fact]
    public void LeadingZeroCountTest()
    {
        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0x00000020), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x00000000)));
            Assert.Equal(new NativeCULong(0x0000001F), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x00000001)));
            Assert.Equal(new NativeCULong(0x00000001), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x7FFFFFFF)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x80000000)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0xFFFFFFFF)));
        }
        else
        {
            Assert.Equal(new NativeCULong(0x00000040), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x00000000)));
            Assert.Equal(new NativeCULong(0x0000003F), BinaryIntegerHelper<NativeCULong>.LeadingZeroCount(new NativeCULong(0x00000001)));
        }
    }

    [Fact]
    public void PopCountTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.PopCount(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000001), BinaryIntegerHelper<NativeCULong>.PopCount(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x0000001F), BinaryIntegerHelper<NativeCULong>.PopCount(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x00000001), BinaryIntegerHelper<NativeCULong>.PopCount(new NativeCULong(0x80000000)));
        Assert.Equal(new NativeCULong(0x00000020), BinaryIntegerHelper<NativeCULong>.PopCount(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void RotateLeftTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.RotateLeft(new NativeCULong(0x00000000), 1));
        Assert.Equal(new NativeCULong(0x00000002), BinaryIntegerHelper<NativeCULong>.RotateLeft(new NativeCULong(0x00000001), 1));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFE), BinaryIntegerHelper<NativeCULong>.RotateLeft(new NativeCULong(0x7FFFFFFF), 1));
            Assert.Equal(new NativeCULong(0x00000001), BinaryIntegerHelper<NativeCULong>.RotateLeft(new NativeCULong(0x80000000), 1));
            Assert.Equal(new NativeCULong(0xFFFFFFFF), BinaryIntegerHelper<NativeCULong>.RotateLeft(new NativeCULong(0xFFFFFFFF), 1));
        }
    }

    [Fact]
    public void RotateRightTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.RotateRight(new NativeCULong(0x00000000), 1));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0x80000000), BinaryIntegerHelper<NativeCULong>.RotateRight(new NativeCULong(0x00000001), 1));
            Assert.Equal(new NativeCULong(0xBFFFFFFF), BinaryIntegerHelper<NativeCULong>.RotateRight(new NativeCULong(0x7FFFFFFF), 1));
            Assert.Equal(new NativeCULong(0x40000000), BinaryIntegerHelper<NativeCULong>.RotateRight(new NativeCULong(0x80000000), 1));
            Assert.Equal(new NativeCULong(0xFFFFFFFF), BinaryIntegerHelper<NativeCULong>.RotateRight(new NativeCULong(0xFFFFFFFF), 1));
        }
    }

    [Fact]
    public void TrailingZeroCountTest()
    {
        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0x00000020), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x00000000)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x00000001)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x7FFFFFFF)));
            Assert.Equal(new NativeCULong(0x0000001F), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x80000000)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0xFFFFFFFF)));
        }
        else
        {
            // 64-bit storage: same low-bit semantics, just a wider zero value.
            Assert.Equal(new NativeCULong(0x00000040), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x00000000)));
            Assert.Equal(new NativeCULong(0x00000000), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x00000001)));
            Assert.Equal(new NativeCULong(0x0000001F), BinaryIntegerHelper<NativeCULong>.TrailingZeroCount(new NativeCULong(0x80000000)));
        }
    }

    [Fact]
    public void GetByteCountTest()
    {
        if (Has32BitStorage)
        {
            Assert.Equal(4, BinaryIntegerHelper<NativeCULong>.GetByteCount(new NativeCULong(0x00000000)));
            Assert.Equal(4, BinaryIntegerHelper<NativeCULong>.GetByteCount(new NativeCULong(0x00000001)));
            Assert.Equal(4, BinaryIntegerHelper<NativeCULong>.GetByteCount(new NativeCULong(0xFFFFFFFF)));
        }
        else
        {
            Assert.Equal(8, BinaryIntegerHelper<NativeCULong>.GetByteCount(new NativeCULong(0x00000000)));
            Assert.Equal(8, BinaryIntegerHelper<NativeCULong>.GetByteCount(new NativeCULong(0x00000001)));
        }
    }

    [Fact]
    public void GetShortestBitLengthTest()
    {
        Assert.Equal(0, BinaryIntegerHelper<NativeCULong>.GetShortestBitLength(new NativeCULong(0x00000000)));
        Assert.Equal(1, BinaryIntegerHelper<NativeCULong>.GetShortestBitLength(new NativeCULong(0x00000001)));
        Assert.Equal(31, BinaryIntegerHelper<NativeCULong>.GetShortestBitLength(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(32, BinaryIntegerHelper<NativeCULong>.GetShortestBitLength(new NativeCULong(0x80000000)));
        Assert.Equal(32, BinaryIntegerHelper<NativeCULong>.GetShortestBitLength(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void TryReadBigEndianTest()
    {
        NativeCULong result;

        if (Has32BitStorage)
        {
            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x00000000), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x01 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x00000001), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x7FFFFFFF), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x80, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x80000000), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0xFFFFFFFF), result);
        }
#if !WINDOWS
        else
        {
            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000000000000UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000000000001UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x000000007FFFFFFFUL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000080000000UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x00000000FFFFFFFFUL), result);
        }
#endif
    }

    [Fact]
    public void TryReadLittleEndianTest()
    {
        NativeCULong result;

        if (Has32BitStorage)
        {
            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x00000000), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x01, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x00000001), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x7FFFFFFF), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x00, 0x00, 0x00, 0x80 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0x80000000), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong(0xFFFFFFFF), result);
        }
#if !WINDOWS
        else
        {
            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000000000000UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000000000001UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x000000007FFFFFFFUL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x0000000080000000UL), result);

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 }, isUnsigned: true, out result));
            Assert.Equal(new NativeCULong((nuint)0x00000000FFFFFFFFUL), result);
        }
#endif
    }

    [Fact]
    public void TryWriteBigEndianTest()
    {
        if (Has32BitStorage)
        {
            Span<byte> destination = stackalloc byte[4];
            int bytesWritten;

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(0x00000000), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(0x00000001), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x01 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(0x7FFFFFFF), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(0x80000000), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x80, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(0xFFFFFFFF), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, destination.ToArray());
        }
#if !WINDOWS
        else
        {
            Span<byte> destination = stackalloc byte[8];
            int bytesWritten;

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong((nuint)0x0000000000000000UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong((nuint)0x0000000000000001UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong((nuint)0x000000007FFFFFFFUL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong((nuint)0x0000000080000000UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong((nuint)0x00000000FFFFFFFFUL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }, destination.ToArray());
        }
#endif
    }

    [Fact]
    public void TryWriteLittleEndianTest()
    {
        if (Has32BitStorage)
        {
            Span<byte> destination = stackalloc byte[4];
            int bytesWritten;

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(0x00000000), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(0x00000001), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(0x7FFFFFFF), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(0x80000000), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x80 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(0xFFFFFFFF), destination, out bytesWritten));
            Assert.Equal(4, bytesWritten);
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, destination.ToArray());
        }
#if !WINDOWS
        else
        {
            Span<byte> destination = stackalloc byte[8];
            int bytesWritten;

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong((nuint)0x0000000000000000UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong((nuint)0x0000000000000001UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong((nuint)0x000000007FFFFFFFUL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong((nuint)0x0000000080000000UL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());

            Assert.True(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong((nuint)0x00000000FFFFFFFFUL), destination, out bytesWritten));
            Assert.Equal(8, bytesWritten);
            Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 }, destination.ToArray());
        }
#endif
    }

    //
    // IBinaryInteger Read/Write Endian — error paths.
    // A 3-byte buffer is smaller than NativeCULong's storage on every platform
    // (4 bytes on Windows/32-bit Unix, 8 bytes on 64-bit Unix), so it hits the
    // < sizeof(NativeType) early-return branch in every implementation variant.
    //

    [Fact]
    public void TryReadBigEndian_SourceTooShort_ReturnsFalse()
    {
        Assert.False(BinaryIntegerHelper<NativeCULong>.TryReadBigEndian(new byte[3], isUnsigned: true, out NativeCULong _));
    }

    [Fact]
    public void TryReadLittleEndian_SourceTooShort_ReturnsFalse()
    {
        Assert.False(BinaryIntegerHelper<NativeCULong>.TryReadLittleEndian(new byte[3], isUnsigned: true, out NativeCULong _));
    }

    [Fact]
    public void TryWriteBigEndian_DestinationTooSmall_ReturnsFalse()
    {
        Span<byte> tooSmall = stackalloc byte[3];
        Assert.False(BinaryIntegerHelper<NativeCULong>.TryWriteBigEndian(new NativeCULong(42u), tooSmall, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    public void TryWriteLittleEndian_DestinationTooSmall_ReturnsFalse()
    {
        Span<byte> tooSmall = stackalloc byte[3];
        Assert.False(BinaryIntegerHelper<NativeCULong>.TryWriteLittleEndian(new NativeCULong(42u), tooSmall, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    //
    // IBinaryNumber
    //

    [Fact]
    public void IsPow2Test()
    {
        Assert.False(BinaryNumberHelper<NativeCULong>.IsPow2(new NativeCULong(0x00000000)));
        Assert.True(BinaryNumberHelper<NativeCULong>.IsPow2(new NativeCULong(0x00000001)));
        Assert.False(BinaryNumberHelper<NativeCULong>.IsPow2(new NativeCULong(0x7FFFFFFF)));
        Assert.True(BinaryNumberHelper<NativeCULong>.IsPow2(new NativeCULong(0x80000000)));
        Assert.False(BinaryNumberHelper<NativeCULong>.IsPow2(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void Log2Test()
    {
        Assert.Equal(new NativeCULong(0x00000000), BinaryNumberHelper<NativeCULong>.Log2(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000000), BinaryNumberHelper<NativeCULong>.Log2(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x0000001E), BinaryNumberHelper<NativeCULong>.Log2(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x0000001F), BinaryNumberHelper<NativeCULong>.Log2(new NativeCULong(0x80000000)));
        Assert.Equal(new NativeCULong(0x0000001F), BinaryNumberHelper<NativeCULong>.Log2(new NativeCULong(0xFFFFFFFF)));
    }

    //
    // IBitwiseOperators
    //

    [Fact]
    public void op_BitwiseAndTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseAnd(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseAnd(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseAnd(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000000), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseAnd(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseAnd(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_BitwiseOrTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseOr(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseOr(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseOr(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseOr(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_BitwiseOr(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_ExclusiveOrTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_ExclusiveOr(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000000), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_ExclusiveOr(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFE), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_ExclusiveOr(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000001), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_ExclusiveOr(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0xFFFFFFFE), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_ExclusiveOr(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_OnesComplementTest()
    {
        Assert.Equal(NativeCULong.MaxValue, BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_OnesComplement(new NativeCULong(0x00000000)));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFE), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_OnesComplement(new NativeCULong(0x00000001)));
            Assert.Equal(new NativeCULong(0x80000000), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_OnesComplement(new NativeCULong(0x7FFFFFFF)));
            Assert.Equal(new NativeCULong(0x7FFFFFFF), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_OnesComplement(new NativeCULong(0x80000000)));
            Assert.Equal(new NativeCULong(0x00000000), BitwiseOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_OnesComplement(new NativeCULong(0xFFFFFFFF)));
        }
    }

    //
    // IComparisonOperators
    //

    [Fact]
    public void op_GreaterThanTest()
    {
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThan(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThan(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThan(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThan(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThan(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_GreaterThanOrEqualTest()
    {
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThanOrEqual(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThanOrEqual(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThanOrEqual(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThanOrEqual(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_GreaterThanOrEqual(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_LessThanTest()
    {
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThan(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThan(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThan(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThan(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThan(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_LessThanOrEqualTest()
    {
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThanOrEqual(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.True(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThanOrEqual(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThanOrEqual(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThanOrEqual(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.False(ComparisonOperatorsHelper<NativeCULong, NativeCULong, bool>.op_LessThanOrEqual(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    //
    // IDecrementOperators
    //

    [Fact]
    public void op_DecrementTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), DecrementOperatorsHelper<NativeCULong>.op_Decrement(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x7FFFFFFE), DecrementOperatorsHelper<NativeCULong>.op_Decrement(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), DecrementOperatorsHelper<NativeCULong>.op_Decrement(new NativeCULong(0x80000000)));
        Assert.Equal(new NativeCULong(0xFFFFFFFE), DecrementOperatorsHelper<NativeCULong>.op_Decrement(new NativeCULong(0xFFFFFFFF)));
        Assert.Equal(NativeCULong.MaxValue, DecrementOperatorsHelper<NativeCULong>.op_Decrement(new NativeCULong(0x00000000)));
    }

    [Fact]
    public void op_CheckedDecrementTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), DecrementOperatorsHelper<NativeCULong>.op_CheckedDecrement(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x7FFFFFFE), DecrementOperatorsHelper<NativeCULong>.op_CheckedDecrement(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), DecrementOperatorsHelper<NativeCULong>.op_CheckedDecrement(new NativeCULong(0x80000000)));
        Assert.Equal(new NativeCULong(0xFFFFFFFE), DecrementOperatorsHelper<NativeCULong>.op_CheckedDecrement(new NativeCULong(0xFFFFFFFF)));

        Assert.Throws<OverflowException>(() => DecrementOperatorsHelper<NativeCULong>.op_CheckedDecrement(new NativeCULong(0x00000000)));
    }

    //
    // IDivisionOperators
    //

    [Fact]
    public void op_DivisionTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0x00000001), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x3FFFFFFF), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x40000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0x80000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));

        Assert.Throws<DivideByZeroException>(() => DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Division(new NativeCULong(0x00000001), new NativeCULong(0)));
    }

    [Fact]
    public void op_CheckedDivisionTest()
    {
        // Unsigned division cannot overflow (the signed MinValue/-1 hazard does not apply),
        // so the checked variant matches plain division for every valid divisor and still
        // throws DivideByZeroException on a zero divisor.
        Assert.Equal(new NativeCULong(0x00000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0x00000001), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x3FFFFFFF), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x40000000), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0x80000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));

        Assert.Throws<DivideByZeroException>(() => DivisionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedDivision(new NativeCULong(0x00000001), new NativeCULong(0)));
    }

    //
    // IEqualityOperators
    //

    [Fact]
    public void op_EqualityTest()
    {
        Assert.True(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Equality(new NativeCULong(0x00000000), new NativeCULong(0)));
        Assert.True(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Equality(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.False(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Equality(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.False(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Equality(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.False(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Equality(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_InequalityTest()
    {
        Assert.False(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Inequality(new NativeCULong(0x00000000), new NativeCULong(0)));
        Assert.False(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Inequality(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.True(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Inequality(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.True(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Inequality(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.True(EqualityOperatorsHelper<NativeCULong, NativeCULong, bool>.op_Inequality(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    //
    // IIncrementOperators
    //

    [Fact]
    public void op_IncrementTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000002), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x80000000), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x80000001), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0x80000000)));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0x00000000), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0xFFFFFFFF)));
        }
#if !WINDOWS
        else
        {
#pragma warning disable CS8778 // intentional 64-bit-storage literal; gated at runtime by Has32BitStorage
            Assert.Equal(new NativeCULong((nuint)0x0000000100000000UL), IncrementOperatorsHelper<NativeCULong>.op_Increment(new NativeCULong(0xFFFFFFFF)));
#pragma warning restore CS8778
        }
#endif
    }

    [Fact]
    public void op_CheckedIncrementTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), IncrementOperatorsHelper<NativeCULong>.op_CheckedIncrement(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000002), IncrementOperatorsHelper<NativeCULong>.op_CheckedIncrement(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x80000000), IncrementOperatorsHelper<NativeCULong>.op_CheckedIncrement(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x80000001), IncrementOperatorsHelper<NativeCULong>.op_CheckedIncrement(new NativeCULong(0x80000000)));

        if (Has32BitStorage)
        {
            Assert.Throws<OverflowException>(() => IncrementOperatorsHelper<NativeCULong>.op_CheckedIncrement(new NativeCULong(0xFFFFFFFF)));
        }
    }

    //
    // IModulusOperators
    //

    [Fact]
    public void op_ModulusTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000001), ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0x00000001), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000001), ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000000), ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0x80000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000001), ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));

        Assert.Throws<DivideByZeroException>(() => ModulusOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Modulus(new NativeCULong(0x00000001), new NativeCULong(0)));
    }

    //
    // IMultiplicativeIdentity
    //

    [Fact]
    public void MultiplicativeIdentityTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), MultiplicativeIdentityHelper<NativeCULong, NativeCULong>.MultiplicativeIdentity);
    }

    //
    // IMultiplyOperators
    //

    [Fact]
    public void op_MultiplyTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000002), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x00000001), new NativeCULong(2)));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFE), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
            Assert.Equal(new NativeCULong(0x00000000), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x80000000), new NativeCULong(2)));
            Assert.Equal(new NativeCULong(0xFFFFFFFE), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));
        }
#if !WINDOWS
        else
        {
#pragma warning disable CS8778 // intentional 64-bit-storage literals; gated at runtime by Has32BitStorage
            Assert.Equal(new NativeCULong((nuint)0x00000000FFFFFFFEUL), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
            Assert.Equal(new NativeCULong((nuint)0x0000000100000000UL), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0x80000000), new NativeCULong(2)));
            Assert.Equal(new NativeCULong((nuint)0x00000001FFFFFFFEUL), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Multiply(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));
#pragma warning restore CS8778
        }
#endif
    }

    [Fact]
    public void op_CheckedMultiplyTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedMultiply(new NativeCULong(0x00000000), new NativeCULong(2)));
        Assert.Equal(new NativeCULong(0x00000002), MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedMultiply(new NativeCULong(0x00000001), new NativeCULong(2)));

        if (Has32BitStorage)
        {
            Assert.Throws<OverflowException>(() => MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedMultiply(new NativeCULong(0x7FFFFFFF), new NativeCULong(2)));
            Assert.Throws<OverflowException>(() => MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedMultiply(new NativeCULong(0x80000000), new NativeCULong(2)));
            Assert.Throws<OverflowException>(() => MultiplyOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedMultiply(new NativeCULong(0xFFFFFFFF), new NativeCULong(2)));
        }
    }

    //
    // INumber
    //

    [Fact]
    public void ClampTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Clamp(new NativeCULong(0x00000000), new NativeCULong(0x01), new NativeCULong(0x3F)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Clamp(new NativeCULong(0x00000001), new NativeCULong(0x01), new NativeCULong(0x3F)));
        Assert.Equal(new NativeCULong(0x0000003F), NumberHelper<NativeCULong>.Clamp(new NativeCULong(0x7FFFFFFF), new NativeCULong(0x01), new NativeCULong(0x3F)));
        Assert.Equal(new NativeCULong(0x0000003F), NumberHelper<NativeCULong>.Clamp(new NativeCULong(0x80000000), new NativeCULong(0x01), new NativeCULong(0x3F)));
        Assert.Equal(new NativeCULong(0x0000003F), NumberHelper<NativeCULong>.Clamp(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x01), new NativeCULong(0x3F)));
    }

    [Fact]
    public void MaxTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Max(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Max(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), NumberHelper<NativeCULong>.Max(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x80000000), NumberHelper<NativeCULong>.Max(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberHelper<NativeCULong>.Max(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void MinTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NumberHelper<NativeCULong>.Min(new NativeCULong(0x00000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Min(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Min(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Min(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Min(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void SignTest()
    {
        Assert.Equal(0, NumberHelper<NativeCULong>.Sign(new NativeCULong(0x00000000)));
        Assert.Equal(1, NumberHelper<NativeCULong>.Sign(new NativeCULong(0x00000001)));
        Assert.Equal(1, NumberHelper<NativeCULong>.Sign(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(1, NumberHelper<NativeCULong>.Sign(new NativeCULong(0x80000000)));
        Assert.Equal(1, NumberHelper<NativeCULong>.Sign(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void AbsTest()
    {
        // Unsigned: Abs is the identity function.
        Assert.Equal(new NativeCULong(0x00000000), NumberHelper<NativeCULong>.Abs(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.Abs(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberHelper<NativeCULong>.Abs(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void CopySignTest()
    {
        // Unsigned: sign is always +; CopySign preserves the magnitude.
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.CopySign(new NativeCULong(0x00000001), new NativeCULong(0x00000005)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberHelper<NativeCULong>.CopySign(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x00000000)));
    }

    [Fact]
    public void MaxMagnitudeTest()
    {
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberHelper<NativeCULong>.MaxMagnitude(new NativeCULong(0x00000000), new NativeCULong(0xFFFFFFFF)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberHelper<NativeCULong>.MaxMagnitude(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x00000001)));
    }

    [Fact]
    public void MinMagnitudeTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NumberHelper<NativeCULong>.MinMagnitude(new NativeCULong(0x00000000), new NativeCULong(0xFFFFFFFF)));
        Assert.Equal(new NativeCULong(0x00000001), NumberHelper<NativeCULong>.MinMagnitude(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x00000001)));
    }

    //
    // INumberBase
    //

    [Fact]
    public void OneTest()
    {
        Assert.Equal(new NativeCULong(0x00000001), NumberBaseHelper<NativeCULong>.One);
    }

    [Fact]
    public void ZeroTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NumberBaseHelper<NativeCULong>.Zero);
    }

    [Fact]
    public void RadixTest()
    {
        Assert.Equal(2, NumberBaseHelper<NativeCULong>.Radix);
    }

    [Fact]
    public void IsCanonicalTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsCanonical(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsCanonical(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsCanonical(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsCanonical(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsCanonical(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsComplexNumberTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsComplexNumber(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsComplexNumber(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsComplexNumber(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsComplexNumber(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsComplexNumber(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsEvenIntegerTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsEvenInteger(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsEvenInteger(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsEvenInteger(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsEvenInteger(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsEvenInteger(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsFiniteTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsFinite(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsFinite(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsFinite(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsFinite(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsFinite(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsImaginaryNumberTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsImaginaryNumber(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsImaginaryNumber(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsImaginaryNumber(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsImaginaryNumber(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsImaginaryNumber(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsInfinityTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsInfinity(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsInfinity(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsInfinity(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsInfinity(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsInfinity(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsIntegerTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsInteger(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsInteger(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsInteger(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsInteger(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsInteger(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsNaNTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsNaN(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNaN(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNaN(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNaN(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNaN(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsNegativeTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegative(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegative(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegative(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegative(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegative(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsNormalTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsNormal(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsNormal(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsNormal(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsNormal(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsNormal(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsOddIntegerTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsOddInteger(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsOddInteger(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsOddInteger(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsOddInteger(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsOddInteger(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsPositiveTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsPositive(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsPositive(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsPositive(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsPositive(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsPositive(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsRealNumberTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsRealNumber(new NativeCULong(0x00000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsRealNumber(new NativeCULong(0x00000001)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsRealNumber(new NativeCULong(0x7FFFFFFF)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsRealNumber(new NativeCULong(0x80000000)));
        Assert.True(NumberBaseHelper<NativeCULong>.IsRealNumber(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsZeroTest()
    {
        Assert.True(NumberBaseHelper<NativeCULong>.IsZero(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsZero(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsZero(new NativeCULong(0x7FFFFFFF)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsZero(new NativeCULong(0x80000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsZero(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsSubnormalTest()
    {
        // Integer types have no subnormals.
        Assert.False(NumberBaseHelper<NativeCULong>.IsSubnormal(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsSubnormal(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsSubnormal(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsNegativeInfinityTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegativeInfinity(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegativeInfinity(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsNegativeInfinity(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void IsPositiveInfinityTest()
    {
        Assert.False(NumberBaseHelper<NativeCULong>.IsPositiveInfinity(new NativeCULong(0x00000000)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsPositiveInfinity(new NativeCULong(0x00000001)));
        Assert.False(NumberBaseHelper<NativeCULong>.IsPositiveInfinity(new NativeCULong(0xFFFFFFFF)));
    }

    [Fact]
    public void MaxMagnitudeNumberTest()
    {
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberBaseHelper<NativeCULong>.MaxMagnitudeNumber(new NativeCULong(0x00000000), new NativeCULong(0xFFFFFFFF)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), NumberBaseHelper<NativeCULong>.MaxMagnitudeNumber(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x00000001)));
    }

    [Fact]
    public void MinMagnitudeNumberTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), NumberBaseHelper<NativeCULong>.MinMagnitudeNumber(new NativeCULong(0x00000000), new NativeCULong(0xFFFFFFFF)));
        Assert.Equal(new NativeCULong(0x00000001), NumberBaseHelper<NativeCULong>.MinMagnitudeNumber(new NativeCULong(0xFFFFFFFF), new NativeCULong(0x00000001)));
    }

    //
    // IShiftOperators
    //

    [Fact]
    public void op_LeftShiftTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x00000000), 1));
        Assert.Equal(new NativeCULong(0x00000002), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x00000001), 1));

        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFE), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x7FFFFFFF), 1));
            Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x80000000), 1));
            Assert.Equal(new NativeCULong(0xFFFFFFFE), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0xFFFFFFFF), 1));
        }
#if !WINDOWS
        else
        {
#pragma warning disable CS8778 // intentional 64-bit-storage literals; gated at runtime by Has32BitStorage
            Assert.Equal(new NativeCULong((nuint)0x00000000FFFFFFFEUL), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x7FFFFFFF), 1));
            Assert.Equal(new NativeCULong((nuint)0x0000000100000000UL), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0x80000000), 1));
            Assert.Equal(new NativeCULong((nuint)0x00000001FFFFFFFEUL), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_LeftShift(new NativeCULong(0xFFFFFFFF), 1));
#pragma warning restore CS8778
        }
#endif
    }

    [Fact]
    public void op_RightShiftTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_RightShift(new NativeCULong(0x00000000), 1));
        Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_RightShift(new NativeCULong(0x00000001), 1));
        Assert.Equal(new NativeCULong(0x3FFFFFFF), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_RightShift(new NativeCULong(0x7FFFFFFF), 1));
        Assert.Equal(new NativeCULong(0x40000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_RightShift(new NativeCULong(0x80000000), 1));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_RightShift(new NativeCULong(0xFFFFFFFF), 1));
    }

    [Fact]
    public void op_UnsignedRightShiftTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_UnsignedRightShift(new NativeCULong(0x00000000), 1));
        Assert.Equal(new NativeCULong(0x00000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_UnsignedRightShift(new NativeCULong(0x00000001), 1));
        Assert.Equal(new NativeCULong(0x3FFFFFFF), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_UnsignedRightShift(new NativeCULong(0x7FFFFFFF), 1));
        Assert.Equal(new NativeCULong(0x40000000), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_UnsignedRightShift(new NativeCULong(0x80000000), 1));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), ShiftOperatorsHelper<NativeCULong, int, NativeCULong>.op_UnsignedRightShift(new NativeCULong(0xFFFFFFFF), 1));
    }

    //
    // ISubtractionOperators
    //

    [Fact]
    public void op_SubtractionTest()
    {
        if (Has32BitStorage)
        {
            Assert.Equal(new NativeCULong(0xFFFFFFFF), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0x00000000), new NativeCULong(1)));
        }
#if !WINDOWS
        else
        {
#pragma warning disable CS8778 // intentional 64-bit-storage literal; gated at runtime by Has32BitStorage
            Assert.Equal(new NativeCULong((nuint)0xFFFFFFFFFFFFFFFFUL), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0x00000000), new NativeCULong(1)));
#pragma warning restore CS8778
        }
#endif

        Assert.Equal(new NativeCULong(0x00000000), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFE), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0xFFFFFFFE), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_Subtraction(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));
    }

    [Fact]
    public void op_CheckedSubtractionTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedSubtraction(new NativeCULong(0x00000001), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFE), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedSubtraction(new NativeCULong(0x7FFFFFFF), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedSubtraction(new NativeCULong(0x80000000), new NativeCULong(1)));
        Assert.Equal(new NativeCULong(0xFFFFFFFE), SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedSubtraction(new NativeCULong(0xFFFFFFFF), new NativeCULong(1)));

        Assert.Throws<OverflowException>(() => SubtractionOperatorsHelper<NativeCULong, NativeCULong, NativeCULong>.op_CheckedSubtraction(new NativeCULong(0x00000000), new NativeCULong(1)));
    }

    //
    // IUnaryNegationOperators
    //
    // NativeCULong is unsigned (mirrors the BCL byte/uint/ulong/nuint contract):
    //   - plain negation wraps modulo 2^N (so -0 == 0 and -1 == MaxValue),
    //   - checked negation throws OverflowException for any non-zero value.

    [Fact]
    public void op_UnaryNegationTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryNegation(new NativeCULong(0x00000000)));
        Assert.Equal(NativeCULong.MaxValue,        UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryNegation(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x00000001), UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryNegation(NativeCULong.MaxValue));
    }

    [Fact]
    public void op_CheckedUnaryNegationTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_CheckedUnaryNegation(new NativeCULong(0x00000000)));
        Assert.Throws<OverflowException>(() => UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_CheckedUnaryNegation(new NativeCULong(0x00000001)));
        Assert.Throws<OverflowException>(() => UnaryNegationOperatorsHelper<NativeCULong, NativeCULong>.op_CheckedUnaryNegation(NativeCULong.MaxValue));
    }

    //
    // IUnaryPlusOperators
    //

    [Fact]
    public void op_UnaryPlusTest()
    {
        Assert.Equal(new NativeCULong(0x00000000), UnaryPlusOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryPlus(new NativeCULong(0x00000000)));
        Assert.Equal(new NativeCULong(0x00000001), UnaryPlusOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryPlus(new NativeCULong(0x00000001)));
        Assert.Equal(new NativeCULong(0x7FFFFFFF), UnaryPlusOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryPlus(new NativeCULong(0x7FFFFFFF)));
        Assert.Equal(new NativeCULong(0x80000000), UnaryPlusOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryPlus(new NativeCULong(0x80000000)));
        Assert.Equal(new NativeCULong(0xFFFFFFFF), UnaryPlusOperatorsHelper<NativeCULong, NativeCULong>.op_UnaryPlus(new NativeCULong(0xFFFFFFFF)));
    }
}
