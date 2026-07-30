using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE2_PRF_PLUS_DERIVE_PARAMS"/>. Used with CKM_IKE2_PRF_PLUS_DERIVE — IKEv2 PRF+ key derivation per RFC 7296 §2.13 (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIke2PrfPlusDeriveParams : MechanismParameters
{
    private readonly byte[] _seedDataBytes;
    private readonly CKM _prfMechanism;
    private readonly bool _hasSeedKey;
    private readonly ulong _seedKey;

    /// <summary>
    /// Initializes IKEv2 PRF+ derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="hasSeedKey">True if <paramref name="seedKey"/> is a valid handle.</param>
    /// <param name="seedKey">Seed-key handle (when <paramref name="hasSeedKey"/> is true).</param>
    /// <param name="seedData">Additional seed data bytes.</param>
    public CkmIke2PrfPlusDeriveParams(CKM prfMechanism, bool hasSeedKey, ulong seedKey, ReadOnlySpan<byte> seedData)
    {
        _seedDataBytes = seedData.ToArray();
        _prfMechanism = prfMechanism;
        _hasSeedKey = hasSeedKey;
        _seedKey = seedKey;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_IKE2_PRF_PLUS_DERIVE_PARAMS
        {
            PrfMechanism = _prfMechanism.ToCULong(),
            HasSeedKey = _hasSeedKey,
            SeedKey = (NativeCULong)_seedKey,
            SeedData = scope.Write(_seedDataBytes),
            SeedDataLen = (NativeCULong)_seedDataBytes.Length,
        };
    }
}
