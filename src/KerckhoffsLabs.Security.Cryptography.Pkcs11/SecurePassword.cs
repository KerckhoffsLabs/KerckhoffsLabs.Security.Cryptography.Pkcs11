using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Holds a password — the input to a password-based key derivation such as PBKDF2 — in a pinned
/// byte buffer that is zeroed on disposal. The counterpart of <see cref="SecurePin"/>, which holds
/// the PIN that logs in to a token.
/// </summary>
/// <remarks>
/// <para>
/// The buffer lives on the pinned object heap, so the garbage collector cannot move it and leave
/// stale copies of the password scattered in memory. Always dispose this instance as soon as the
/// password is no longer needed; the finalizer is a safety net, not a substitute for deterministic
/// disposal.
/// </para>
/// <para>
/// It differs from <see cref="SecurePin"/> where a password differs from a PIN: it may be empty, which
/// PBKDF2 accepts, and text is encoded the way <see cref="Rfc2898DeriveBytes"/> encodes it
/// (<see cref="Encoding.UTF8"/>, where an unpaired surrogate becomes U+FFFD), so the same password
/// derives the same key on the token as in the BCL.
/// </para>
/// </remarks>
public sealed class SecurePassword : IDisposable
{
    private byte[] _buffer;
    private bool _disposed;

    /// <summary>Initializes a new <see cref="SecurePassword"/> from password bytes. The bytes are copied.</summary>
    /// <param name="password">The password bytes, typically UTF-8. May be empty.</param>
    public SecurePassword(ReadOnlySpan<byte> password)
    {
        _buffer = GC.AllocateArray<byte>(password.Length, pinned: true);
        password.CopyTo(_buffer);
    }

    /// <summary>Initializes a new <see cref="SecurePassword"/> from characters, encoded as UTF-8.</summary>
    /// <remarks>
    /// The preferred input when the password is typed or read into a <c>char[]</c> or
    /// <c>stackalloc</c> buffer: it is encoded straight into this instance's pinned buffer, so no
    /// string and no intermediate byte array ever holds the password. Zero your own character buffer
    /// once this returns.
    /// </remarks>
    /// <param name="password">The password characters. May be empty.</param>
    public SecurePassword(ReadOnlySpan<char> password)
    {
        _buffer = GC.AllocateArray<byte>(Encoding.UTF8.GetByteCount(password), pinned: true);
        Encoding.UTF8.GetBytes(password, _buffer);
    }

    /// <summary>Initializes a new <see cref="SecurePassword"/> from a string, encoded as UTF-8.</summary>
    /// <remarks>
    /// The string itself remains in managed memory and cannot be reliably zeroed — strings are
    /// immutable and may be interned. Prefer the <see cref="SecurePassword(ReadOnlySpan{char})"/>
    /// overload if you can avoid putting the password in a string at all.
    /// </remarks>
    /// <param name="password">The password string. May be empty.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="password"/> is null.</exception>
    public SecurePassword(string password)
        : this(password is null ? throw new ArgumentNullException(nameof(password)) : password.AsSpan())
    {
    }

    /// <summary>The password bytes, for the interop layer only. Valid until <see cref="Dispose"/> is called.</summary>
    /// <remarks>
    /// Internal on purpose: a container for a secret offers no public way to read it back, so the
    /// password cannot be logged or copied out through this type.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the password has been disposed.</exception>
    internal ReadOnlySpan<byte> Password
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The length of the password in bytes.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the password has been disposed.</exception>
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    /// <summary>Zeroes the underlying buffer.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = [];
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — zeroes the password even if Dispose was not called.</summary>
    ~SecurePassword() => Dispose();

    /// <summary>
    /// Returns a non-revealing marker, so that accidentally formatting a <see cref="SecurePassword"/>
    /// into a log message cannot leak the password. Length and contents are never disclosed.
    /// </summary>
    public override string ToString() => "SecurePassword{redacted}";
}
