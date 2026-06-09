using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class SecureBufferTests
{
    [Fact]
    public void Constructor_AllocatesRequestedLength()
    {
        using var buf = new SecureBuffer(16);
        Assert.Equal(16, buf.Length);
        Assert.All(buf.Span.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void Constructor_RejectsNonPositiveLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer(-1));
    }

    [Fact]
    public void Span_AllowsReadWrite()
    {
        using var buf = new SecureBuffer(4);
        buf.Span[0] = 0xAA;
        buf.Span[3] = 0xBB;
        Assert.Equal(0xAA, buf.Span[0]);
        Assert.Equal(0xBB, buf.Span[3]);
    }

    [Fact]
    public void Span_AfterDispose_ThrowsObjectDisposed()
    {
        var buf = new SecureBuffer(4);
        buf.Dispose();
        // Span<byte> is a ref struct — accessing it via a statement-body lambda avoids
        // the ref-struct-in-expression-discard compile error.
        Assert.Throws<ObjectDisposedException>(() => { Span<byte> _ = buf.Span; });
    }

    [Fact]
    public void Length_AfterDispose_ThrowsObjectDisposed()
    {
        var buf = new SecureBuffer(4);
        buf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = buf.Length);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var buf = new SecureBuffer(4);
        buf.Dispose();
        Assert.Null(Record.Exception(buf.Dispose)); // idempotent — must not throw
    }

    [Fact]
    public void Dispose_ZeroesBuffer()
    {
        var buf = new SecureBuffer(4);
        buf.Span.Fill(0xCC);
        var field = typeof(SecureBuffer).GetField("_buffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        byte[] inner = (byte[])field!.GetValue(buf)!;
        Assert.Equal(0xCC, inner[0]);
        buf.Dispose();
        Assert.All(inner, b => Assert.Equal(0, b));
    }
}
