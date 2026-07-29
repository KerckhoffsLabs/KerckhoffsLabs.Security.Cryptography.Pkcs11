using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_GCM_PARAMS"/>. Owns the unmanaged buffers
/// for the IV and AAD. Dispose this instance AFTER the <see cref="Mechanism"/> that
/// holds a reference to it has been disposed.
/// </summary>
public sealed class CkmAesGcmParams : MechanismParameters
{
    private CK_GCM_PARAMS _lowLevelParams;
    private IntPtr _iv;
    private IntPtr _aad;
    private readonly byte[] _ivBytes;
    private readonly byte[] _aadBytes;
    private readonly int _tagBits;
    private bool _disposed;

    /// <summary>
    /// Initializes the GCM parameters.
    /// </summary>
    /// <param name="iv">Initialization vector (typically 12 bytes / 96 bits).</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="tagBits">Authentication tag length in bits; must be a multiple of 8 in [32, 128]. Use 128 unless you have a specific reason.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="iv"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="tagBits"/> is not a multiple of 8 in [32, 128].</exception>
    public CkmAesGcmParams(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, int tagBits)
    {
        if (iv.IsEmpty) throw new ArgumentException("IV must not be empty.", nameof(iv));
        if (tagBits < 32 || tagBits > 128 || (tagBits % 8) != 0)
            throw new ArgumentOutOfRangeException(nameof(tagBits), "Tag size must be a multiple of 8 in [32, 128] bits.");

        _iv = UnmanagedMemory.Allocate(iv.Length);
        UnmanagedMemory.Write(_iv, iv);

        if (!aad.IsEmpty)
        {
            _aad = UnmanagedMemory.Allocate(aad.Length);
            UnmanagedMemory.Write(_aad, aad);
        }

        _ivBytes = iv.ToArray();
        _aadBytes = aad.IsEmpty ? [] : aad.ToArray();
        _tagBits = tagBits;

        _lowLevelParams = new()
        {
            Iv = _iv,
            IvLen = (NativeCULong)iv.Length,
            // Legacy field; PKCS#11 v3.2 §2.5.13 allows 0 and the IV length is taken from IvLen.
            // Some tokens reject a non-zero value (SoftHSM's AES-GCM KAT fails when it is set), so
            // leave it 0 for maximum interoperability. NSS softoken's classic C_EncryptInit GCM path
            // conversely rejects 0, so GCM against NSS goes through the message-based AesGcmPkcs11
            // façade (C_MessageEncrypt), not this classic-params path.
            IvBits = (NativeCULong)0,
            AAD = _aad,
            AADLen = (NativeCULong)aad.Length,
            TagBits = (NativeCULong)tagBits,
        };
    }

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
        return new CK_GCM_PARAMS
        {
            Iv = scope.Write(_ivBytes),
            IvLen = (NativeCULong)_ivBytes.Length,
            // Legacy field; PKCS#11 v3.2 §2.5.13 allows 0 and the IV length is taken from IvLen.
            // Some tokens reject a non-zero value (SoftHSM's AES-GCM KAT fails when it is set), so
            // leave it 0 for maximum interoperability. NSS softoken's classic C_EncryptInit GCM path
            // conversely rejects 0, so GCM against NSS goes through the message-based AesGcmPkcs11
            // façade (C_MessageEncrypt), not this classic-params path.
            IvBits = (NativeCULong)0,
            AAD = scope.Write(_aadBytes),
            AADLen = (NativeCULong)_aadBytes.Length,
            TagBits = (NativeCULong)_tagBits,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _iv);
        UnmanagedMemory.Free(ref _aad);
        _lowLevelParams.Iv = IntPtr.Zero;
        _lowLevelParams.AAD = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmAesGcmParams() => Dispose(false);
}
