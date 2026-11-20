using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Holds a PIN value in a pinned byte buffer that is zeroed on disposal.
/// Prefer this over raw <c>byte[]</c> or <see langword="string"/> when passing PINs to PKCS#11.
/// For the password of a password-based key derivation, use <see cref="SecurePassword"/>.
/// </summary>
/// <remarks>
/// The buffer is allocated on the pinned object heap, so the garbage collector never moves it and
/// cannot leave stale copies of the PIN scattered in memory.
/// Always dispose this instance as soon as the PIN is no longer needed; the finalizer is a
/// safety net, not a substitute for deterministic disposal.
/// </remarks>
public sealed class SecurePin : IDisposable
{
    private readonly Lock _lock = new();
    private byte[] _buffer;
    private bool _disposed;
    // Uses in progress (BeginUse): a disposal meanwhile zeroes the buffer when the last one ends.
    private int _uses;

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
        _buffer = GC.AllocateArray<byte>(utf8Pin.Length, pinned: true);
        utf8Pin.CopyTo(_buffer);
    }

    /// <summary>Initializes a new <see cref="SecurePin"/> from characters, encoded as UTF-8.</summary>
    /// <remarks>
    /// <para>
    /// The preferred input when the PIN is typed or read into a <c>char[]</c> or <see langword="stackalloc"/>
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

        _buffer = GC.AllocateArray<byte>(byteCount, pinned: true);
        StrictUtf8.GetBytes(pin, _buffer);
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
    /// <exception cref="ObjectDisposedException">Thrown if the pin has been disposed, and no use of it is in progress.</exception>
    internal ReadOnlySpan<byte> Pin
    {
        get
        {
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed && _uses == 0, this);
                return _buffer;
            }
        }
    }

    /// <summary>Whether <see cref="Dispose"/> was called.</summary>
    internal bool IsDisposed => Volatile.Read(ref _disposed);

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

    /// <summary>
    /// Starts a use of the PIN by the library (a check against refused PINs, a send, the record of its answer), which
    /// its caller may dispose meanwhile on another thread: the PIN is then zeroed once the use ends, so the module is
    /// never sent a PIN zeroed half way, which would cost a retry.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the pin has been disposed.</exception>
    internal Use BeginUse()
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _uses++;
        }
        return new Use(this);
    }

    /// <summary>A use of the PIN (<see cref="BeginUse"/>); ends when disposed.</summary>
    /// <remarks>
    /// A class, not a struct, so that it ends exactly once: a copy of a struct disposed twice would end two uses, drive
    /// the count below zero, and leave the PIN unzeroed by every later <see cref="SecurePin.Dispose"/>, or zero it under
    /// another use still in progress.
    /// </remarks>
    internal sealed class Use(SecurePin pin) : IDisposable
    {
        private int _ended;

        /// <summary>Ends the use; zeroes the PIN if it was disposed meanwhile and this was its last use. Idempotent.</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _ended, 1) == 0)
                pin.EndUse();
        }
    }

    private void EndUse()
    {
        lock (_lock)
        {
            if (--_uses == 0 && _disposed)
                Zero();
        }
    }

    /// <summary>Zeroes the underlying buffer, at once or, while the library uses the PIN, once it is done.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            if (_uses == 0)
                Zero();
        }
        GC.SuppressFinalize(this);
    }

    // Under _lock.
    private void Zero()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = [];
    }

    /// <summary>Finalizer safety net — zeroes the buffer even if Dispose was not called.</summary>
    /// <remarks>
    /// Takes no lock: a finalizer runs only once the instance is unreachable, and a <see cref="Use"/> in progress keeps
    /// it reachable, so nothing else can touch the buffer. It also runs on an instance whose constructor threw: the
    /// string overload throws while computing the argument of the constructor it chains to, before any field
    /// initializer has run, so <c>_lock</c> and <c>_buffer</c> are still null there, and locking would throw on the
    /// finalizer thread and end the process.
    /// </remarks>
    ~SecurePin()
    {
        if (_buffer is not null)
            CryptographicOperations.ZeroMemory(_buffer);
    }

    /// <summary>
    /// Returns a non-revealing marker. Overridden so that accidentally formatting
    /// a <see cref="SecurePin"/> into a log message (or any string template) cannot
    /// leak the PIN bytes. Length and contents are never disclosed.
    /// </summary>
    public override string ToString() => "SecurePin{redacted}";
}
