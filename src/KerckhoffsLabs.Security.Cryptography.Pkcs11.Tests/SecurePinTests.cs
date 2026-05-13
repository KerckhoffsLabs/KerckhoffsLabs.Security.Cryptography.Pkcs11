using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Security;

public sealed class SecurePinTests
{
    [Fact]
    public void Constructor_FromSpan_CopiesBytes()
    {
        byte[] source = Encoding.UTF8.GetBytes("hunter2");
        using var pin = new SecurePin(source);
        Assert.Equal(source.Length, pin.Length);
        Assert.True(pin.Pin.SequenceEqual(source));
    }

    [Fact]
    public void Constructor_FromString_EncodesUtf8()
    {
        using var pin = new SecurePin("hunter2");
        byte[] expected = Encoding.UTF8.GetBytes("hunter2");
        Assert.True(pin.Pin.SequenceEqual(expected));
    }

    [Fact]
    public void Constructor_RejectsNullString()
        => Assert.Throws<ArgumentNullException>(() => new SecurePin((string)null!));

    [Fact]
    public void Constructor_FromSpan_RejectsEmpty()
        => Assert.Throws<ArgumentException>(() => new SecurePin(ReadOnlySpan<byte>.Empty));

    [Fact]
    public void Constructor_FromString_RejectsEmpty()
        => Assert.Throws<ArgumentException>(() => new SecurePin(""));

    [Fact]
    public void Pin_AfterDispose_ThrowsObjectDisposed()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = pin.Pin);
    }

    [Fact]
    public void Length_AfterDispose_ThrowsObjectDisposed()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = pin.Length);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        pin.Dispose(); // must not throw
    }

    [Fact]
    public void Dispose_ZeroesUnderlyingBuffer()
    {
        var pin = new SecurePin("hunter2");
        var field = typeof(SecurePin).GetField("_buffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(field);
        byte[] buffer = (byte[])field!.GetValue(pin)!;
        Assert.NotEqual(0, buffer[0]); // pre-condition: buffer holds PIN bytes
        pin.Dispose();
        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}
