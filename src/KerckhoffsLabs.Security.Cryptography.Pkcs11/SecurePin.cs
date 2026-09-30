using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Holds a PIN value in a pinned byte buffer that is zeroed on disposal.
/// Prefer this over raw <c>byte[]</c> or <c>string</c> when passing PINs to PKCS#11.
/// For the password of a password-based key derivation, use <see cref="SecurePassword"/>.
/// </summary>
/// <remarks>
/// The buffer is pinned via <see cref="GCHandle.Alloc(object, GCHandleType)"/> so the
/// garbage collector cannot move it and leave stale copies of the PIN scattered in memory.
/// Always dispose this instance as soon as the PIN is no longer needed; the finalizer is a
/// safety net, not a substitute for deterministic disposal.
/// </remarks>
public sealed class SecurePin : IDisposable
{
    private byte[] _buffer;
    private GCHandle _pin;
    private bool _disposed;

    // Strict UTF-8: a lone surrogate in a PIN is refused instead of being silently replaced with
    // U+FFFD, which would log in with different bytes from the ones the user typed.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Initializes a new <see cref="SecurePin"/> from a PIN already encoded as UTF-8. The bytes are copied.</summary>
    /// <remarks>
    /// The bytes are sent to the token as given. PKCS#11 PINs are <c>CK_UTF8CHAR</c> strings and tokens
    /// compare them byte for byte, so no Unicode normalization is applied.
    /// </remarks>
    /// <param name="utf8Pin">The UTF-8 PIN bytes. Must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="utf8Pin"/> is empty.</exception>
    public SecurePin(ReadOnlySpan<byte> utf8Pin)
    {
        if (utf8Pin.IsEmpty) throw new ArgumentException("PIN must not be empty.", nameof(utf8Pin));
        _buffer = new byte[utf8Pin.Length];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
        try
        {
            utf8Pin.CopyTo(_buffer);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>Initializes a new <see cref="SecurePin"/> from characters, encoded as UTF-8.</summary>
    /// <remarks>
    /// <para>
    /// The preferred input when the PIN is typed or read into a <c>char[]</c> or <c>stackalloc</c>
    /// buffer: it is encoded straight into this instance's pinned buffer, so no string and no
    /// intermediate byte array ever holds the PIN. Zero your own character buffer once this returns.
    /// </para>
    /// <para>No Unicode normalization is applied; tokens compare PIN bytes exactly.</para>
    /// </remarks>
    /// <param name="pin">The PIN characters. Must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="pin"/> is empty, or contains an
    /// unpaired surrogate and so has no UTF-8 encoding.</exception>
    public SecurePin(ReadOnlySpan<char> pin)
    {
        if (pin.IsEmpty) throw new ArgumentException("PIN must not be empty.", nameof(pin));
        int byteCount;
        try
        {
            byteCount = StrictUtf8.GetByteCount(pin);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException("PIN is not valid UTF-16 text (unpaired surrogate).", nameof(pin), ex);
        }

        _buffer = new byte[byteCount];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
        try
        {
            StrictUtf8.GetBytes(pin, _buffer);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>Initializes a new <see cref="SecurePin"/> from a string, encoded as UTF-8.</summary>
    /// <remarks>
    /// The string itself remains in managed memory and cannot be reliably zeroed — strings are
    /// immutable and may be interned. Prefer the <see cref="SecurePin(ReadOnlySpan{char})"/> overload
    /// if you can avoid putting the PIN in a string at all.
    /// </remarks>
    /// <param name="pin">The PIN string. Must not be null.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="pin"/> is empty, or contains an
    /// unpaired surrogate.</exception>
    public SecurePin(string pin)
        : this(pin is null ? throw new ArgumentNullException(nameof(pin)) : pin.AsSpan())
    {
    }

    /// <summary>The PIN bytes, for the interop layer only. Valid until <see cref="Dispose"/> is called.</summary>
    /// <remarks>
    /// Internal on purpose: a container for a secret offers no public way to read it back, so the PIN
    /// cannot be logged or copied out through this type. The interop layer takes this span straight to
    /// the native call, so the PIN is never duplicated into a transient array that a caller must
    /// remember to zero, and that a GC compaction could relocate — leaving an unzeroed PIN image
    /// behind — between the copy and the zeroing. The only plaintext image is this buffer, pinned for
    /// its lifetime and zeroed by <see cref="Dispose"/>.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the pin has been disposed.</exception>
    internal ReadOnlySpan<byte> Pin
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The length of the PIN in bytes.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the pin has been disposed.</exception>
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    /// <summary>Zeroes the underlying buffer and releases the GC pin.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        if (_pin.IsAllocated) _pin.Free();
        _buffer = [];
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — release pin even if Dispose was not called.</summary>
    ~SecurePin() => Dispose();

    /// <summary>
    /// Returns a non-revealing marker. Overridden so that accidentally formatting
    /// a <see cref="SecurePin"/> into a log message (or any string template) cannot
    /// leak the PIN bytes. Length and contents are never disclosed.
    /// </summary>
    public override string ToString() => "SecurePin{redacted}";
}
