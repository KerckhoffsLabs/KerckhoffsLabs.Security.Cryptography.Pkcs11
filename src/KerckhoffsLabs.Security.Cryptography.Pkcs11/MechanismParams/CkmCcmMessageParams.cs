using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CCM_MESSAGE_PARAMS"/>. Used with the v3.0
/// message-based AEAD API on CKM_AES_CCM. Note that CCM requires the data length to
/// be known up front.
/// </summary>
public sealed class CkmCcmMessageParams : MechanismParameters
{
    private readonly int _macLen;
    private readonly int _dataLen;
    private readonly byte[] _nonceBytes;
    // The MAC as managed state, and what CopyMacTo serves. For decrypt it is seeded from the
    // caller's MAC. For encrypt AbsorbOutput fills it from the scope-owned block the token wrote.
    private readonly byte[] _macBuffer;

    /// <summary>For encryption — wrapper allocates the MAC output buffer of <paramref name="macBytes"/>.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative or too long for the nonce's length field (RFC 3610), or <paramref name="macBytes"/> is not one of {4, 6, 8, 10, 12, 14, 16}.</exception>
    public static CkmCcmMessageParams ForEncrypt(int dataLen, ReadOnlySpan<byte> nonce, int macBytes)
        => new(dataLen, nonce, macBytes, default);

    /// <summary>For decryption — wrapper stores caller's MAC bytes for the library to verify.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative or too long for the nonce's length field (RFC 3610), or the length of <paramref name="mac"/> is not one of {4, 6, 8, 10, 12, 14, 16} bytes.</exception>
    public static CkmCcmMessageParams ForDecrypt(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> mac)
        => new(dataLen, nonce, mac.Length, mac);

    private CkmCcmMessageParams(int dataLen, ReadOnlySpan<byte> nonce, int macLen, ReadOnlySpan<byte> macInput)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.Length is < 7 or > 13)
            throw new ArgumentException("CCM nonce must be 7..13 bytes (RFC 3610).", nameof(nonce));
        // RFC 3610 §2.1 encodes the data length in L = 15 - nonce length bytes, so it must be below
        // 2^(8L). With an int length, only 13- and 12-byte nonces leave a field it can overflow.
        int lengthFieldBits = 8 * (15 - nonce.Length);
        if (lengthFieldBits < 31 && dataLen >= 1 << lengthFieldBits)
            throw new ArgumentOutOfRangeException(nameof(dataLen), dataLen,
                $"A {nonce.Length}-byte CCM nonce leaves a {15 - nonce.Length}-byte length field, so the data must be shorter than {1 << lengthFieldBits} bytes (RFC 3610).");
        if (macLen is not 4 and not 6 and not 8 and not 10 and not 12 and not 14 and not 16)
            throw new ArgumentOutOfRangeException(nameof(macLen), "CCM MAC length must be 4/6/8/10/12/14/16 bytes.");

        _macLen = macLen;
        _dataLen = dataLen;
        _nonceBytes = nonce.ToArray();

        _macBuffer = new byte[macLen];
        if (!macInput.IsEmpty) macInput.CopyTo(_macBuffer);
    }

    /// <summary>The MAC length, in bytes, for the crypto policies' MAC-length check.</summary>
    internal int MacLength => _macLen;

    /// <summary>Copies the MAC bytes (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than the MAC length.</exception>
    public void CopyMacTo(Span<byte> destination)
    {
        if (destination.Length < _macLen)
            throw new ArgumentException($"Destination must be at least {_macLen} bytes.", nameof(destination));
        _macBuffer.AsSpan(0, _macLen).CopyTo(destination);
    }

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_CCM_MESSAGE_PARAMS
        {
            DataLen = (NativeCULong)_dataLen,
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            NonceFixedBits = (NativeCULong)0,
            NonceGenerator = (NativeCULong)0, // CKG_NO_GENERATE
            Mac = scope.Write(_macBuffer),
            MacLen = (NativeCULong)_macLen,
        });
    }

    /// <inheritdoc/>
    internal override bool AbsorbsTokenOutput => true;

    internal override void AbsorbOutput(Pkcs11ParameterBlock block)
    {
        var s = block.Read<CK_CCM_MESSAGE_PARAMS>();
        if (s.Mac == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Mac, _macBuffer.AsSpan(0, _macLen));
    }
}
