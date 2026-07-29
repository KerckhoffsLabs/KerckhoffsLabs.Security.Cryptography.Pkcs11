using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS"/>. Used
/// with the v3.0 message-based AEAD API on CKM_CHACHA20_POLY1305 and CKM_SALSA20_POLY1305.
/// The Poly1305 tag is fixed at 16 bytes.
/// </summary>
public sealed class CkmSalsa20ChaCha20Poly1305MsgParams : MechanismParameters
{
    private const int Poly1305TagLen = 16;

    private CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS _lowLevelParams;
    private IntPtr _nonce;
    private IntPtr _tag;
    private readonly byte[] _nonceBytes;
    // Holds the token's output after AbsorbOutput; the legacy _tag buffer is what CopyTagTo still
    // reads until the session switches to the scope path (see AbsorbedTag).
    private readonly byte[] _tagBuffer;
    private bool _disposed;

    /// <summary>For encryption — wrapper allocates a 16-byte zero-filled tag buffer.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is empty.</exception>
    public static CkmSalsa20ChaCha20Poly1305MsgParams ForEncrypt(ReadOnlySpan<byte> nonce)
        => new(nonce, default);

    /// <summary>For decryption — wrapper stores caller's 16-byte tag for the library to verify.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is empty, or <paramref name="tag"/> is not 16 bytes long.</exception>
    public static CkmSalsa20ChaCha20Poly1305MsgParams ForDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag)
    {
        if (tag.Length != Poly1305TagLen)
            throw new ArgumentException($"Tag must be {Poly1305TagLen} bytes.", nameof(tag));
        return new CkmSalsa20ChaCha20Poly1305MsgParams(nonce, tag);
    }

    private CkmSalsa20ChaCha20Poly1305MsgParams(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tagInput)
    {
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _nonceBytes = nonce.ToArray();
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _tag = UnmanagedMemory.Allocate(Poly1305TagLen);
        if (!tagInput.IsEmpty)
            UnmanagedMemory.Write(_tag, tagInput);

        _tagBuffer = new byte[Poly1305TagLen];
        if (!tagInput.IsEmpty) tagInput.CopyTo(_tagBuffer);

        _lowLevelParams = new()
        {
            Nonce = _nonce,
            NonceLen = (NativeCULong)nonce.Length,
            Tag = _tag,
        };
    }

    /// <summary>Copies the 16-byte tag (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the parameters have been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than 16 bytes.</exception>
    public void CopyTagTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < Poly1305TagLen)
            throw new ArgumentException($"Destination must be at least {Poly1305TagLen} bytes.", nameof(destination));
        UnmanagedMemory.Read(_tag, destination[..Poly1305TagLen]);
    }

    /// <summary>The managed tag buffer that <see cref="AbsorbOutput"/> fills. Used by tests until
    /// the session switches to the scope path, after which <see cref="CopyTagTo"/> reads it.</summary>
    internal ReadOnlySpan<byte> AbsorbedTag => _tagBuffer.AsSpan(0, Poly1305TagLen);

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
        {
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            Tag = scope.Write(_tagBuffer),
        };
    }

    /// <inheritdoc/>
    internal override void AbsorbOutput(object marshalled)
    {
        var s = (CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)marshalled;
        if (s.Tag == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Tag, _tagBuffer.AsSpan(0, Poly1305TagLen));
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _nonce);
        UnmanagedMemory.Free(ref _tag);
        _lowLevelParams.Nonce = IntPtr.Zero;
        _lowLevelParams.Tag = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSalsa20ChaCha20Poly1305MsgParams() => Dispose(false);
}
