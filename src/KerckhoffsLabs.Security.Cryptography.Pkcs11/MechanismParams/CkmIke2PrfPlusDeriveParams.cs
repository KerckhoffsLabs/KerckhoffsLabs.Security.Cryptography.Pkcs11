using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE2_PRF_PLUS_DERIVE_PARAMS"/>. Used with CKM_IKE2_PRF_PLUS_DERIVE — IKEv2 PRF+ key derivation per RFC 7296 §2.13 (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke2PrfPlusDeriveParams : MechanismParameters
{
    private CK_IKE2_PRF_PLUS_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _seedData;
    private readonly byte[] _seedDataBytes;
    private bool _disposed;

    /// <summary>
    /// Initializes IKEv2 PRF+ derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="hasSeedKey">True if <paramref name="seedKey"/> is a valid handle.</param>
    /// <param name="seedKey">Seed-key handle (when <paramref name="hasSeedKey"/> is true).</param>
    /// <param name="seedData">Additional seed data bytes.</param>
    public CkmIke2PrfPlusDeriveParams(CKM prfMechanism, bool hasSeedKey, ulong seedKey, ReadOnlySpan<byte> seedData)
    {
        if (!seedData.IsEmpty)
        {
            _seedData = UnmanagedMemory.Allocate(seedData.Length);
            UnmanagedMemory.Write(_seedData, seedData);
        }

        _seedDataBytes = seedData.ToArray();

        _lowLevelParams = new()
        {
            PrfMechanism = (NativeCULong)(ulong)prfMechanism,
            HasSeedKey = hasSeedKey,
            SeedKey = (NativeCULong)seedKey,
            SeedData = _seedData,
            SeedDataLen = (NativeCULong)seedData.Length,
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
        return new CK_IKE2_PRF_PLUS_DERIVE_PARAMS
        {
            PrfMechanism = _lowLevelParams.PrfMechanism,
            HasSeedKey = _lowLevelParams.HasSeedKey,
            SeedKey = _lowLevelParams.SeedKey,
            SeedData = scope.Write(_seedDataBytes),
            SeedDataLen = (NativeCULong)_seedDataBytes.Length,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _seedData);
        _lowLevelParams.SeedData = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmIke2PrfPlusDeriveParams() => Dispose(false);
}
