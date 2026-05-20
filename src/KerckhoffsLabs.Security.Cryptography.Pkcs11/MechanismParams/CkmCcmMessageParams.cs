using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CCM_MESSAGE_PARAMS"/>. Used with the v3.0
/// message-based AEAD API on CKM_AES_CCM. Note that CCM requires the data length to
/// be known up front.
/// </summary>
public sealed class CkmCcmMessageParams : IMechanismParams
{
    private CK_CCM_MESSAGE_PARAMS _lowLevelParams;
    private IntPtr _nonce;
    private IntPtr _mac;
    private readonly int _macLen;
    private bool _disposed;

    /// <summary>For encryption — wrapper allocates the MAC output buffer of <paramref name="macBytes"/>.</summary>
    public static CkmCcmMessageParams ForEncrypt(int dataLen, ReadOnlySpan<byte> nonce, int macBytes)
        => new CkmCcmMessageParams(dataLen, nonce, macBytes, default);

    /// <summary>For decryption — wrapper stores caller's MAC bytes for the library to verify.</summary>
    public static CkmCcmMessageParams ForDecrypt(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> mac)
        => new CkmCcmMessageParams(dataLen, nonce, mac.Length, mac);

    private CkmCcmMessageParams(int dataLen, ReadOnlySpan<byte> nonce, int macLen, ReadOnlySpan<byte> macInput)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.Length < 7 || nonce.Length > 13)
            throw new ArgumentException("CCM nonce must be 7..13 bytes (RFC 3610).", nameof(nonce));
        if (macLen != 4 && macLen != 6 && macLen != 8 && macLen != 10 && macLen != 12 && macLen != 14 && macLen != 16)
            throw new ArgumentOutOfRangeException(nameof(macLen), "CCM MAC length must be 4/6/8/10/12/14/16 bytes.");

        _macLen = macLen;
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _mac = UnmanagedMemory.Allocate(macLen);
        if (!macInput.IsEmpty)
            UnmanagedMemory.Write(_mac, macInput);

        _lowLevelParams = new CK_CCM_MESSAGE_PARAMS
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
    public void CopyMacTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _macLen)
            throw new ArgumentException($"Destination must be at least {_macLen} bytes.", nameof(destination));
        unsafe { fixed (byte* d = destination) Buffer.MemoryCopy((void*)_mac, d, destination.Length, _macLen); }
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _nonce);
        UnmanagedMemory.Free(ref _mac);
        _lowLevelParams.Nonce = IntPtr.Zero;
        _lowLevelParams.Mac = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmCcmMessageParams() => Dispose();
}
