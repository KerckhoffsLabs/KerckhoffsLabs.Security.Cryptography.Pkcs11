namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Boundary;

/// <summary>
/// The guard-page buffers the boundary tests rely on: each buffer is flush against a page the process
/// cannot read, on the side asked for, and is itself fully usable. If these did not hold, the boundary
/// tests would pass over the overruns they exist to catch.
/// </summary>
public sealed class GuardedMemoryTests
{
    public static TheoryData<int, GuardSide> Shapes => new()
    {
        { 0, GuardSide.After }, { 1, GuardSide.After }, { 13, GuardSide.After },
        { Environment.SystemPageSize, GuardSide.After }, { Environment.SystemPageSize + 5, GuardSide.After },
        { 1, GuardSide.Before }, { 13, GuardSide.Before }, { Environment.SystemPageSize + 5, GuardSide.Before },
    };

    [Theory]
    [MemberData(nameof(Shapes))]
    public void Buffer_IsFlushAgainstItsGuardPage(int length, GuardSide side)
    {
        using var memory = GuardedMemory.Allocate(length, side);

        Assert.Equal(length, memory.Span.Length);
        if (side == GuardSide.After)
            Assert.Equal(memory.GuardPage, memory.Address + length);
        else
            Assert.Equal(memory.GuardPage + Environment.SystemPageSize, memory.Address);
    }

    [Theory]
    [MemberData(nameof(Shapes))]
    public void GuardPage_CannotBeRead(int length, GuardSide side)
    {
        using var memory = GuardedMemory.Allocate(length, side);

        Assert.False(GuardedMemory.IsReadable(memory.GuardPage));
        Assert.False(GuardedMemory.IsReadable(memory.GuardPage + Environment.SystemPageSize - 1));
    }

    [Theory]
    [MemberData(nameof(Shapes))]
    public void EveryByteOfTheBuffer_IsZeroedReadableAndWritable(int length, GuardSide side)
    {
        using var memory = GuardedMemory.Allocate(length, side);
        Span<byte> span = memory.Span;

        Assert.True(span.IndexOfAnyExcept((byte)0) < 0);
        span.Fill(0xA5);
        Assert.True(span.IndexOfAnyExcept((byte)0xA5) < 0);
        if (length > 0)
        {
            Assert.True(GuardedMemory.IsReadable(memory.Address));
            Assert.True(GuardedMemory.IsReadable(memory.Address + length - 1));
        }
    }

    [Fact]
    public void Of_CopiesTheContents()
    {
        using var memory = GuardedMemory.Of("boundary"u8);

        Assert.True(memory.Span.SequenceEqual("boundary"u8));
    }

    [Fact]
    public void Span_AfterDispose_Throws()
    {
        var memory = GuardedMemory.Allocate(8);
        memory.Dispose();

        Assert.Throws<ObjectDisposedException>(() => memory.Span.Length);
    }
}
