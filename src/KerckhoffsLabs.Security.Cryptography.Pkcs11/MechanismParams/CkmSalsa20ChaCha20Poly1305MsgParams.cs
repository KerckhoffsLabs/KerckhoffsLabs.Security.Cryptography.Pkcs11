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
    private bool _disposed;

    /// <summary>For encryption — wrapper allocates a 16-byte zero-filled tag buffer.</summary>
    public static CkmSalsa20ChaCha20Poly1305MsgParams ForEncrypt(ReadOnlySpan<byte> nonce)
        => new(nonce, default);

    /// <summary>For decryption — wrapper stores caller's 16-byte tag for the library to verify.</summary>
    public static CkmSalsa20ChaCha20Poly1305MsgParams ForDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag)
    {
        if (tag.Length != Poly1305TagLen)
            throw new ArgumentException($"Tag must be {Poly1305TagLen} bytes.", nameof(tag));
        return new CkmSalsa20ChaCha20Poly1305MsgParams(nonce, tag);
    }

    private CkmSalsa20ChaCha20Poly1305MsgParams(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tagInput)
    {
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _tag = UnmanagedMemory.Allocate(Poly1305TagLen);
        if (!tagInput.IsEmpty)
            UnmanagedMemory.Write(_tag, tagInput);

        _lowLevelParams = new()
        {
            Nonce = _nonce,
            NonceLen = (NativeCULong)nonce.Length,
            Tag = _tag,
        };
    }

    /// <summary>Copies the 16-byte tag (output of encrypt) into the caller's buffer.</summary>
    public void CopyTagTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < Poly1305TagLen)
            throw new ArgumentException($"Destination must be at least {Poly1305TagLen} bytes.", nameof(destination));
        UnmanagedMemory.Read(_tag, destination[..Poly1305TagLen]);
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
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
