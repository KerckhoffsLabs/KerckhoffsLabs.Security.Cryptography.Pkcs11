using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="SecurePassword"/> is <see cref="SecurePin"/>'s counterpart for key-derivation passwords:
/// the same no-read-back, zero-on-dispose contract, but empty values are allowed and text is encoded
/// the way <see cref="Rfc2898DeriveBytes"/> encodes it.
/// </summary>
public sealed class SecurePasswordTests
{
    [Fact]
    public void Constructor_FromSpan_CopiesBytes()
    {
        byte[] source = "hunter2"u8.ToArray();
        using var password = new SecurePassword(source);

        source.AsSpan().Clear();

        Assert.Equal("hunter2"u8.ToArray(), password.Password.ToArray());
    }

    [Fact]
    public void Constructor_FromStringAndChars_EncodeUtf8()
    {
        using var fromString = new SecurePassword("pässwörd");
        using var fromChars = new SecurePassword("pässwörd".AsSpan());

        Assert.Equal("pässwörd"u8.ToArray(), fromString.Password.ToArray());
        Assert.Equal("pässwörd"u8.ToArray(), fromChars.Password.ToArray());
    }

    [Fact]
    public void Constructor_EncodesAnUnpairedSurrogateAsRfc2898DeriveBytesDoes()
    {
        // Rfc2898DeriveBytes encodes with Encoding.UTF8, which substitutes U+FFFD; refusing instead,
        // as SecurePin does, would derive a different key from the same password.
        using var password = new SecurePassword("1\uD8002");

        Assert.Equal(Encoding.UTF8.GetBytes("1\uD8002"), password.Password.ToArray());
    }

    [Fact]
    public void EmptyPassword_IsAccepted()
    {
        using var fromString = new SecurePassword("");
        using var fromSpan = new SecurePassword(ReadOnlySpan<byte>.Empty);

        Assert.Equal(0, fromString.Length);
        Assert.Equal(0, fromSpan.Length);
    }

    [Fact]
    public void Constructor_RejectsNullString() =>
        Assert.Throws<ArgumentNullException>(() => new SecurePassword((string)null!));

    /// <summary>A secret container offers no public read-back; only the interop layer sees the bytes.</summary>
    [Fact]
    public void PasswordBytes_AreNotPubliclyReadable()
    {
        var property = typeof(SecurePassword).GetProperty(
            "Password",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(property);
        Assert.False(property!.GetMethod!.IsPublic);
    }

    [Fact]
    public void AfterDispose_PasswordAndLengthThrow_AndDisposeIsIdempotent()
    {
        var password = new SecurePassword("hunter2");
        password.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = password.Password);
        Assert.Throws<ObjectDisposedException>(() => _ = password.Length);
        Assert.Null(Record.Exception(password.Dispose));
    }

    [Fact]
    public void ToString_IsRedacted()
    {
        using var password = new SecurePassword("hunter2");

        Assert.Equal("SecurePassword{redacted}", password.ToString());
    }

    [Fact]
    public unsafe void Password_IsThePinnedBuffer_NotACopy()
    {
        using var password = new SecurePassword("hunter2");

        IntPtr first, second;
        fixed (byte* p = password.Password) first = (IntPtr)p;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        fixed (byte* p = password.Password) second = (IntPtr)p;

        Assert.Equal(first, second);
    }

    [Fact]
    public void Dispose_ZeroesUnderlyingBuffer()
    {
        var password = new SecurePassword("hunter2");
        var field = typeof(SecurePassword).GetField("_buffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(field);
        byte[] buffer = (byte[])field!.GetValue(password)!;
        Assert.NotEqual(0, buffer[0]);

        password.Dispose();

        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}
