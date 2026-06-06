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
    private bool _disposed;

    /// <summary>For encryption — the wrapper allocates a zero-filled tag buffer of
    /// <paramref name="tagBytes"/>; the library writes into it during C_EncryptMessage.
    /// Read the result via <see cref="CopyTagTo"/> after the call.</summary>
    public static CkmGcmMessageParams ForEncrypt(ReadOnlySpan<byte> iv, int tagBytes)
        => new(iv, tagBytes, default);

    /// <summary>For decryption — the wrapper stores the caller's tag bytes; the library
    /// reads them during C_DecryptMessage and verifies the AEAD authentication.</summary>
    public static CkmGcmMessageParams ForDecrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> tag)
        => new(iv, tag.Length, tag);

    private CkmGcmMessageParams(ReadOnlySpan<byte> iv, int tagLen, ReadOnlySpan<byte> tagInput)
    {
        if (iv.IsEmpty) throw new ArgumentException("IV must not be empty.", nameof(iv));
        if (tagLen is < 4 or > 16) throw new ArgumentOutOfRangeException(nameof(tagLen), "GCM tag length must be 4..16 bytes.");

        _tagLen = tagLen;
        _iv = UnmanagedMemory.Allocate(iv.Length);
        UnmanagedMemory.Write(_iv, iv);

        _tag = UnmanagedMemory.Allocate(tagLen);
        if (!tagInput.IsEmpty)
            UnmanagedMemory.Write(_tag, tagInput);

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
    public void CopyTagTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _tagLen)
            throw new ArgumentException($"Destination must be at least {_tagLen} bytes.", nameof(destination));
        unsafe { fixed (byte* d = destination) Buffer.MemoryCopy((void*)_tag, d, destination.Length, _tagLen); }
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _iv);
        UnmanagedMemory.Free(ref _tag);
        _lowLevelParams.Iv = IntPtr.Zero;
        _lowLevelParams.Tag = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmGcmMessageParams() => Dispose();
}
