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
    private CK_CCM_MESSAGE_PARAMS _lowLevelParams;
    private IntPtr _nonce;
    private IntPtr _mac;
    private readonly int _macLen;
    private readonly int _dataLen;
    private readonly byte[] _nonceBytes;
    // Holds the token's output after AbsorbOutput; the legacy _mac buffer is what CopyMacTo still
    // reads until the session switches to the scope path (see AbsorbedMac).
    private readonly byte[] _macBuffer;
    private bool _disposed;

    /// <summary>For encryption — wrapper allocates the MAC output buffer of <paramref name="macBytes"/>.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative, or <paramref name="macBytes"/> is not one of {4, 6, 8, 10, 12, 14, 16}.</exception>
    public static CkmCcmMessageParams ForEncrypt(int dataLen, ReadOnlySpan<byte> nonce, int macBytes)
        => new(dataLen, nonce, macBytes, default);

    /// <summary>For decryption — wrapper stores caller's MAC bytes for the library to verify.</summary>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative, or the length of <paramref name="mac"/> is not one of {4, 6, 8, 10, 12, 14, 16} bytes.</exception>
    public static CkmCcmMessageParams ForDecrypt(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> mac)
        => new(dataLen, nonce, mac.Length, mac);

    private CkmCcmMessageParams(int dataLen, ReadOnlySpan<byte> nonce, int macLen, ReadOnlySpan<byte> macInput)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.Length is < 7 or > 13)
            throw new ArgumentException("CCM nonce must be 7..13 bytes (RFC 3610).", nameof(nonce));
        if (macLen is not 4 and not 6 and not 8 and not 10 and not 12 and not 14 and not 16)
            throw new ArgumentOutOfRangeException(nameof(macLen), "CCM MAC length must be 4/6/8/10/12/14/16 bytes.");

        _macLen = macLen;
        _dataLen = dataLen;
        _nonceBytes = nonce.ToArray();
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _mac = UnmanagedMemory.Allocate(macLen);
        if (!macInput.IsEmpty)
            UnmanagedMemory.Write(_mac, macInput);

        _macBuffer = new byte[macLen];
        if (!macInput.IsEmpty) macInput.CopyTo(_macBuffer);

        _lowLevelParams = new()
        {
            DataLen = (NativeCULong)dataLen,
            Nonce = _nonce,
            NonceLen = (NativeCULong)nonce.Length,
            NonceFixedBits = (NativeCULong)0,
            NonceGenerator = (NativeCULong)0, // CKG_NO_GENERATE
            Mac = _mac,
            MacLen = (NativeCULong)macLen,
        };
    }

    /// <summary>Copies the MAC bytes (output of encrypt) into the caller's buffer.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the parameters have been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is smaller than the MAC length.</exception>
    public void CopyMacTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _macLen)
            throw new ArgumentException($"Destination must be at least {_macLen} bytes.", nameof(destination));
        UnmanagedMemory.Read(_mac, destination[.._macLen]);
    }

    /// <summary>The managed MAC buffer that <see cref="AbsorbOutput"/> fills. Used by tests until
    /// the session switches to the scope path, after which <see cref="CopyMacTo"/> reads it.</summary>
    internal ReadOnlySpan<byte> AbsorbedMac => _macBuffer.AsSpan(0, _macLen);

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
        return new CK_CCM_MESSAGE_PARAMS
        {
            DataLen = (NativeCULong)_dataLen,
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            NonceFixedBits = (NativeCULong)0,
            NonceGenerator = (NativeCULong)0, // CKG_NO_GENERATE
            Mac = scope.Write(_macBuffer),
            MacLen = (NativeCULong)_macLen,
        };
    }

    /// <inheritdoc/>
    internal override void AbsorbOutput(object marshalled)
    {
        var s = (CK_CCM_MESSAGE_PARAMS)marshalled;
        if (s.Mac == IntPtr.Zero) return;
        UnmanagedMemory.Read(s.Mac, _macBuffer.AsSpan(0, _macLen));
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _nonce);
        UnmanagedMemory.Free(ref _mac);
        _lowLevelParams.Nonce = IntPtr.Zero;
        _lowLevelParams.Mac = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmCcmMessageParams() => Dispose(false);
}
