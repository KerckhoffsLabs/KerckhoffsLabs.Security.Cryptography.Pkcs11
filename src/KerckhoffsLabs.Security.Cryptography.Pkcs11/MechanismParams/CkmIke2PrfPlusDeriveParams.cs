using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE2_PRF_PLUS_DERIVE_PARAMS"/>. Used with CKM_IKE2_PRF_PLUS_DERIVE — IKEv2 PRF+ key derivation per RFC 7296 §2.13 (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// A seed key must come from the workspace that performs the derive; it is resolved to its object
/// handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmIke2PrfPlusDeriveParams : MechanismParameters
{
    private readonly byte[] _seedDataBytes;
    private readonly CKM _prfMechanism;
    private readonly Pkcs11Key? _seedKey;

    /// <summary>
    /// Initializes IKEv2 PRF+ derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="seedKey">Seed key, or <c>null</c> when there is none.</param>
    /// <param name="seedData">Additional seed data bytes.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="seedKey"/> has no secret-key object.</exception>
    public CkmIke2PrfPlusDeriveParams(CKM prfMechanism, Pkcs11Key? seedKey, ReadOnlySpan<byte> seedData)
    {
        seedKey?.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(seedKey));

        _seedDataBytes = seedData.ToArray();
        _prfMechanism = prfMechanism;
        _seedKey = seedKey;
    }

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_IKE2_PRF_PLUS_DERIVE_PARAMS
        {
            PrfMechanism = CkULong.From((ulong)_prfMechanism, "prfMechanism"),
            HasSeedKey = CkBbool.From(_seedKey is not null),
            SeedKey = _seedKey is null ? default : scope.KeyHandle(_seedKey, KeyHandlePart.Private, "seedKey"),
            SeedData = scope.Write(_seedDataBytes),
            SeedDataLen = (NativeCULong)_seedDataBytes.Length,
        });
    }
}
