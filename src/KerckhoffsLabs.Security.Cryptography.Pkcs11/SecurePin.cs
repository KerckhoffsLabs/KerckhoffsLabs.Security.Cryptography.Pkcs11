using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Holds a PIN value in a pinned byte buffer that is zeroed on disposal.
/// Prefer this over raw <c>byte[]</c> or <c>string</c> when passing PINs to PKCS#11.
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

    /// <summary>Initializes a new <see cref="SecurePin"/> from a span of bytes. The bytes are copied.</summary>
    /// <param name="pin">The PIN bytes. Must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="pin"/> is empty.</exception>
    public SecurePin(ReadOnlySpan<byte> pin)
    {
        if (pin.IsEmpty) throw new ArgumentException("PIN must not be empty.", nameof(pin));
        _buffer = new byte[pin.Length];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
        try
        {
            pin.CopyTo(_buffer);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>Initializes a new <see cref="SecurePin"/> from a string using UTF-8 encoding.</summary>
    /// <remarks>
    /// The transient byte[] used to encode the string is zeroed before this constructor returns.
    /// The string itself remains in managed memory and cannot be reliably zeroed — strings are
    /// immutable and may be interned. Prefer the <see cref="ReadOnlySpan{T}"/> overload if you
    /// can avoid putting the PIN in a string at all.
    /// </remarks>
    /// <param name="pin">The PIN string. Must not be null.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the encoded PIN is empty.</exception>
    public SecurePin(string pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        int byteCount = Encoding.UTF8.GetByteCount(pin);
        if (byteCount == 0) throw new ArgumentException("PIN must not be empty.", nameof(pin));
        byte[] tmp = new byte[byteCount];
        try
        {
            Encoding.UTF8.GetBytes(pin, tmp);
            _buffer = new byte[byteCount];
            _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            try
            {
                Array.Copy(tmp, _buffer, byteCount);
            }
            catch
            {
                Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>Returns a read-only span over the PIN bytes. Valid until <see cref="Dispose"/> is called.</summary>
    public ReadOnlySpan<byte> Pin
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The length of the PIN in bytes.</summary>
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
