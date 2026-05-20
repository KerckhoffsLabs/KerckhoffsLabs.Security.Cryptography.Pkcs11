using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Internal transient buffer for sensitive bytes (PINs, key material intermediates).
/// Pinned via <see cref="GCHandle"/> so the GC cannot move it and leave stale copies
/// in memory, and zeroed on <see cref="Dispose"/> via
/// <see cref="CryptographicOperations.ZeroMemory"/>.
/// </summary>
/// <remarks>
/// Always dispose this instance as soon as the sensitive bytes are no longer needed;
/// the finalizer is a safety net, not a substitute for deterministic disposal.
///
/// The constructor does not require a try/catch around post-<see cref="GCHandle.Alloc(object, GCHandleType)"/>
/// code because the runtime zero-initializes the new <c>byte[]</c> — there is no
/// mutation step that could throw after the pin is taken. If the constructor ever grows
/// a post-Alloc initialization step, apply the canonical try/catch pattern from
/// <see cref="SecurePin"/> (wrap the mutation in try, call <see cref="Dispose"/> in catch).
/// </remarks>
internal sealed class SecureBuffer : IDisposable
{
    private byte[] _buffer;
    private GCHandle _pin;
    private bool _disposed;

    /// <summary>Allocates a zero-filled buffer of the given length and pins it.</summary>
    /// <param name="length">The buffer length in bytes. Must be &gt; 0.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if <paramref name="length"/> is &lt;= 0.
    /// </exception>
    public SecureBuffer(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        _buffer = new byte[length];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
    }

    /// <summary>
    /// Read/write span over the buffer. Valid until <see cref="Dispose"/> is called.
    /// </summary>
    /// <remarks>
    /// Intentionally mutable — callers write data into this buffer (e.g., encoding a PIN into
    /// UTF-8 bytes) before passing it on. Contrast with <see cref="SecurePin.Pin"/>, which is
    /// read-only because the PIN is immutable after construction.
    /// Do not retain a span across a disposal boundary; retained spans will silently read zeroes
    /// rather than throwing.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown after <see cref="Dispose"/>.</exception>
    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The buffer length in bytes.</summary>
    /// <exception cref="ObjectDisposedException">Thrown after <see cref="Dispose"/>.</exception>
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    /// <summary>Zeroes the buffer and releases the GC pin.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        if (_pin.IsAllocated) _pin.Free();
        _buffer = Array.Empty<byte>();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — zeroes and releases the pin even if Dispose was not called.</summary>
    ~SecureBuffer() => Dispose();

    /// <summary>
    /// Returns a non-revealing marker. Overridden so that accidentally formatting
    /// a <see cref="SecureBuffer"/> into a log message cannot leak the buffer
    /// contents. Length and contents are never disclosed.
    /// </summary>
    public override string ToString() => "SecureBuffer{redacted}";
}
