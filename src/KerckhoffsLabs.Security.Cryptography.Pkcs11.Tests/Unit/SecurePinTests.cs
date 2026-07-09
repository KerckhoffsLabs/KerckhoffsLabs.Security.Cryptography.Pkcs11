using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SecurePinTests
{
    [Fact]
    public void Constructor_FromSpan_CopiesBytes()
    {
        byte[] source = Encoding.UTF8.GetBytes("hunter2");
        using var pin = new SecurePin(source);
        Assert.Equal(source.Length, pin.Length);
        Assert.Equal(source, pin.Pin.ToArray());
    }

    [Fact]
    public void Constructor_FromString_EncodesUtf8()
    {
        using var pin = new SecurePin("hunter2");
        byte[] expected = Encoding.UTF8.GetBytes("hunter2");
        Assert.Equal(expected, pin.Pin.ToArray());
    }

    [Fact]
    public void Constructor_RejectsNullString()
        => Assert.Throws<ArgumentNullException>(() => new SecurePin((string)null!));

    [Fact]
    public void Constructor_FromSpan_RejectsEmpty()
        => Assert.Throws<ArgumentException>(() => new SecurePin([]));

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
        Assert.Null(Record.Exception(pin.Dispose)); // idempotent — must not throw
    }

    [Fact]
    public void ToString_IsRedacted_AndLeaksNoPinBytes()
    {
        using var pin = new SecurePin("hunter2");
        Assert.Equal("SecurePin{redacted}", pin.ToString());
        Assert.DoesNotContain("hunter2", pin.ToString());
    }

    [Fact]
    public void ToPinnedArray_CopiesBytes_IndependentOfSource()
    {
        byte[] source = Encoding.UTF8.GetBytes("hunter2");
        using var pin = new SecurePin(source);

        byte[] first = pin.ToPinnedArray();
        byte[] second = pin.ToPinnedArray();

        Assert.Equal(source, first);
        Assert.NotSame(first, second); // fresh transient per call — each is zeroed by its own consumer

        // Zeroing the transient (the consumer's contract) must not disturb the SecurePin itself.
        Array.Clear(first);
        Assert.Equal(source, pin.Pin.ToArray());
    }

    [Fact]
    public void ToPinnedArray_AfterDispose_ThrowsObjectDisposed()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pin.ToPinnedArray());
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
