using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_GCM_MESSAGE_PARAMS"/>. Used with the v3.0
/// message-based AEAD API (C_EncryptMessage / C_DecryptMessage) on CKM_AES_GCM.
/// </summary>
public sealed class CkmGcmMessageParams : MechanismParameters
{
    private readonly int _tagLen;
    private readonly byte[] _ivBytes;
    // The tag as managed state, and what CopyTagTo serves. For decrypt it is seeded from the
    // caller's tag. For encrypt AbsorbOutput fills it from the scope-owned block the token wrote.
    private readonly byte[] _tagBuffer;

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

        _tagBuffer = new byte[tagLen];
        if (!tagInput.IsEmpty) tagInput.CopyTo(_tagBuffer);
    }

    /// <summary>Copies the tag bytes (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than the tag length.</exception>
    public void CopyTagTo(Span<byte> destination)
    {
        if (destination.Length < _tagLen)
            throw new ArgumentException($"Destination must be at least {_tagLen} bytes.", nameof(destination));
        _tagBuffer.AsSpan(0, _tagLen).CopyTo(destination);
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
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
    /// <inheritdoc/>
    internal override bool AbsorbsTokenOutput => true;

    internal override void AbsorbOutput(object marshalled)
    {

        var s = (CK_GCM_MESSAGE_PARAMS)marshalled;
        if (s.Tag == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Tag, _tagBuffer.AsSpan(0, _tagLen));
    }
}
