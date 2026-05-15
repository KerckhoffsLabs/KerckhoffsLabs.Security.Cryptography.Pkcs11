using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_HKDF_PARAMS"/>. Used with CKM_HKDF_DERIVE / CKM_HKDF_DATA / CKM_HKDF_KEY_GEN (PKCS#11 v3.0).
/// </summary>
public sealed class CkmHkdfParams : IMechanismParams
{
    private CK_HKDF_PARAMS _lowLevelParams;
    private IntPtr _salt;
    private IntPtr _info;
    private bool _disposed;

    /// <summary>
    /// Initializes the HKDF parameters.
    /// </summary>
    /// <param name="extract">Perform the HKDF-Extract step.</param>
    /// <param name="expand">Perform the HKDF-Expand step.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="saltType">Salt type: 1 = SALT_NULL, 2 = SALT_DATA, 4 = SALT_KEY.</param>
    /// <param name="salt">Salt bytes when saltType = SALT_DATA; pass <c>default</c> otherwise.</param>
    /// <param name="saltKey">Salt key handle when saltType = SALT_KEY; pass 0 otherwise.</param>
    /// <param name="info">Application-specific context bytes.</param>
    public CkmHkdfParams(bool extract, bool expand, CKM prfHashMechanism, ulong saltType, ReadOnlySpan<byte> salt, ulong saltKey, ReadOnlySpan<byte> info)
    {
        if (!salt.IsEmpty)
        {
            _salt = UnmanagedMemory.Allocate(salt.Length);
            UnmanagedMemory.Write(_salt, salt);
        }

        if (!info.IsEmpty)
        {
            _info = UnmanagedMemory.Allocate(info.Length);
            UnmanagedMemory.Write(_info, info);
        }

        _lowLevelParams = new CK_HKDF_PARAMS
        {
            Extract = extract,
            Expand = expand,
            PrfHashMechanism = (NativeCULong)(ulong)prfHashMechanism,
            SaltType = (NativeCULong)saltType,
            Salt = _salt,
            SaltLen = (NativeCULong)salt.Length,
            SaltKey = (NativeCULong)saltKey,
            Info = _info,
            InfoLen = (NativeCULong)info.Length,
        };
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
        UnmanagedMemory.Free(ref _salt);
        UnmanagedMemory.Free(ref _info);
        _lowLevelParams.Salt = IntPtr.Zero;
        _lowLevelParams.Info = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmHkdfParams() => Dispose();
}
