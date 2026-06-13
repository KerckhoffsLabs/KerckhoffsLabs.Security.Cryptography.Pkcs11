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
    private bool _disposed;

    /// <summary>For encryption — wrapper allocates the MAC output buffer of <paramref name="macBytes"/>.</summary>
    public static CkmCcmMessageParams ForEncrypt(int dataLen, ReadOnlySpan<byte> nonce, int macBytes)
        => new(dataLen, nonce, macBytes, default);

    /// <summary>For decryption — wrapper stores caller's MAC bytes for the library to verify.</summary>
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
        _nonce = UnmanagedMemory.Allocate(nonce.Length);
        UnmanagedMemory.Write(_nonce, nonce);

        _mac = UnmanagedMemory.Allocate(macLen);
        if (!macInput.IsEmpty)
            UnmanagedMemory.Write(_mac, macInput);

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
    public void CopyMacTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _macLen)
            throw new ArgumentException($"Destination must be at least {_macLen} bytes.", nameof(destination));
        UnmanagedMemory.Read(_mac, destination[.._macLen]);
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
        UnmanagedMemory.Free(ref _mac);
        _lowLevelParams.Nonce = IntPtr.Zero;
        _lowLevelParams.Mac = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmCcmMessageParams() => Dispose(false);
}
