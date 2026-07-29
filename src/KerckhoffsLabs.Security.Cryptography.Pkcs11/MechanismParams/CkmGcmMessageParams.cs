using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_GCM_MESSAGE_PARAMS"/>. Used with the v3.0
/// message-based AEAD API (C_EncryptMessage / C_DecryptMessage) on CKM_AES_GCM.
/// </summary>
public sealed class CkmGcmMessageParams : MechanismParameters
{
    private CK_GCM_MESSAGE_PARAMS _lowLevelParams;
    private IntPtr _iv;
    private IntPtr _tag;
    private readonly int _tagLen;
    private readonly byte[] _ivBytes;
    // The tag as managed state, and what CopyTagTo serves. Seeded from the caller's tag for decrypt;
    // filled by AbsorbOutput from the scope-owned block the token wrote for encrypt.
    private readonly byte[] _tagBuffer;
    private bool _disposed;

    /// <summary>For encryption — the wrapper allocates a zero-filled tag buffer of
    /// <paramref name="tagBytes"/>; the library writes into it during C_EncryptMessage.
    /// Read the result via <see cref="CopyTagTo"/> after the call.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="iv"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="tagBytes"/> is not in [4, 16].</exception>
    public static CkmGcmMessageParams ForEncrypt(ReadOnlySpan<byte> iv, int tagBytes)
        => new(iv, tagBytes, default);

    /// <summary>For decryption — the wrapper stores the caller's tag bytes; the library
    /// reads them during C_DecryptMessage and verifies the AEAD authentication.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="iv"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the length of <paramref name="tag"/> is not in [4, 16] bytes.</exception>
    public static CkmGcmMessageParams ForDecrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> tag)
        => new(iv, tag.Length, tag);

    private CkmGcmMessageParams(ReadOnlySpan<byte> iv, int tagLen, ReadOnlySpan<byte> tagInput)
    {
        if (iv.IsEmpty) throw new ArgumentException("IV must not be empty.", nameof(iv));
        if (tagLen is < 4 or > 16) throw new ArgumentOutOfRangeException(nameof(tagLen), "GCM tag length must be 4..16 bytes.");

        _tagLen = tagLen;
        _ivBytes = iv.ToArray();
        _iv = UnmanagedMemory.Allocate(iv.Length);
        UnmanagedMemory.Write(_iv, iv);

        _tag = UnmanagedMemory.Allocate(tagLen);
        if (!tagInput.IsEmpty)
            UnmanagedMemory.Write(_tag, tagInput);

        _tagBuffer = new byte[tagLen];
        if (!tagInput.IsEmpty) tagInput.CopyTo(_tagBuffer);

        _lowLevelParams = new()
        {
            Iv = _iv,
            IvLen = (NativeCULong)iv.Length,
            IvFixedBits = (NativeCULong)0,
            IvGenerator = (NativeCULong)0, // CKG_NO_GENERATE
            Tag = _tag,
            TagBits = (NativeCULong)(tagLen * 8),
        };
    }

    /// <summary>Copies the tag bytes (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the parameters have been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than the tag length.</exception>
    public void CopyTagTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _tagLen)
            throw new ArgumentException($"Destination must be at least {_tagLen} bytes.", nameof(destination));
        _tagBuffer.AsSpan(0, _tagLen).CopyTo(destination);
    }

    /// <summary>The managed tag buffer that <see cref="AbsorbOutput"/> fills, and that
    /// <see cref="CopyTagTo"/> serves callers from.</summary>
    internal ReadOnlySpan<byte> AbsorbedTag => _tagBuffer.AsSpan(0, _tagLen);

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
        return new CK_GCM_MESSAGE_PARAMS
        {
            Iv = scope.Write(_ivBytes),
            IvLen = (NativeCULong)_ivBytes.Length,
            IvFixedBits = (NativeCULong)0,
            IvGenerator = (NativeCULong)0, // CKG_NO_GENERATE
            Tag = scope.Write(_tagBuffer),
            TagBits = (NativeCULong)(_tagLen * 8),
        };
    }

    /// <inheritdoc/>
    internal override void AbsorbOutput(object marshalled)
    {
        // Catches absorbing after this object has been disposed. It cannot catch the other ordering
        // mistake — a scope already released while these params are still live — because nothing here
        // can observe that; the pointers in `marshalled` would simply address freed memory. Keeping
        // the absorb inside the scope's lifetime remains the caller's responsibility.
        ObjectDisposedException.ThrowIf(_disposed, this);

        var s = (CK_GCM_MESSAGE_PARAMS)marshalled;
        if (s.Tag == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Tag, _tagBuffer.AsSpan(0, _tagLen));
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _iv);
        UnmanagedMemory.Free(ref _tag);
        _lowLevelParams.Iv = IntPtr.Zero;
        _lowLevelParams.Tag = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmGcmMessageParams() => Dispose(false);
}
