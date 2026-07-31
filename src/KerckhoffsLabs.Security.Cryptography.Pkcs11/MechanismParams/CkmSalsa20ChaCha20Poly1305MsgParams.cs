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

    private readonly byte[] _nonceBytes;
    // The tag as managed state, and what CopyTagTo serves. Seeded from the caller's tag for decrypt;
    // filled by AbsorbOutput from the scope-owned block the token wrote for encrypt.
    private readonly byte[] _tagBuffer;

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

        _tagBuffer = new byte[Poly1305TagLen];
        if (!tagInput.IsEmpty) tagInput.CopyTo(_tagBuffer);
    }

    /// <summary>Copies the 16-byte tag (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than 16 bytes.</exception>
    public void CopyTagTo(Span<byte> destination)
    {
        if (destination.Length < Poly1305TagLen)
            throw new ArgumentException($"Destination must be at least {Poly1305TagLen} bytes.", nameof(destination));
        _tagBuffer.AsSpan(0, Poly1305TagLen).CopyTo(destination);
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
        {
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            Tag = scope.Write(_tagBuffer),
        };
    }

    /// <inheritdoc/>
    /// <inheritdoc/>
    internal override bool AbsorbsTokenOutput => true;

    internal override void AbsorbOutput(object marshalled)
    {

        var s = (CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)marshalled;
        if (s.Tag == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Tag, _tagBuffer.AsSpan(0, Poly1305TagLen));
    }
}
