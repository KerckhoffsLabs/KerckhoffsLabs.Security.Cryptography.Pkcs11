using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_HKDF_PARAMS"/>. Used with CKM_HKDF_DERIVE / CKM_HKDF_DATA / CKM_HKDF_KEY_GEN (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// Each factory fixes the salt source, so the salt type sent to the token always agrees with the salt
/// that was supplied: <see cref="WithoutSalt"/> (RFC 5869's default salt), <see cref="WithSalt"/>
/// (salt bytes), or <see cref="WithSaltKey"/> (the value of an on-token key).
/// </remarks>
public sealed class CkmHkdfParams : MechanismParameters
{
    private readonly byte[] _saltBytes;
    private readonly byte[] _infoBytes;
    private readonly bool _extract;
    private readonly bool _expand;
    private readonly CKM _prfHashMechanism;
    private readonly HkdfSaltType _saltType;
    private readonly Pkcs11Key? _saltKey;

    private CkmHkdfParams(HkdfOperation operation, CKM prfHashMechanism, HkdfSaltType saltType,
        ReadOnlySpan<byte> salt, Pkcs11Key? saltKey, ReadOnlySpan<byte> info)
    {
        (_extract, _expand) = operation switch
        {
            HkdfOperation.ExtractOnly => (true, false),
            HkdfOperation.ExpandOnly => (false, true),
            HkdfOperation.ExtractAndExpand => (true, true),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Not a defined HkdfOperation member."),
        };
        _saltBytes = salt.IsEmpty ? [] : salt.ToArray();
        _infoBytes = info.IsEmpty ? [] : info.ToArray();
        _prfHashMechanism = prfHashMechanism;
        _saltType = saltType;
        _saltKey = saltKey;
    }

    /// <summary>
    /// HKDF parameters with no salt (<c>CKF_HKDF_SALT_NULL</c>): the token uses RFC 5869's default of
    /// HashLen zero bytes.
    /// </summary>
    /// <param name="operation">Which HKDF step(s) to perform.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="info">Application-specific context bytes.</param>
    /// <returns>The parameters.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="operation"/> is not a defined <see cref="HkdfOperation"/> member.</exception>
    public static CkmHkdfParams WithoutSalt(HkdfOperation operation, CKM prfHashMechanism, ReadOnlySpan<byte> info = default) =>
        new(operation, prfHashMechanism, HkdfSaltType.Null, default, null, info);

    /// <summary>
    /// HKDF parameters salted with <paramref name="salt"/> (<c>CKF_HKDF_SALT_DATA</c>).
    /// </summary>
    /// <param name="operation">Which HKDF step(s) to perform.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="salt">Salt bytes. Must not be empty.</param>
    /// <param name="info">Application-specific context bytes.</param>
    /// <returns>The parameters.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="salt"/> is empty; use <see cref="WithoutSalt"/> for RFC 5869's default salt, which some tokens refuse to accept as empty salt data.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="operation"/> is not a defined <see cref="HkdfOperation"/> member.</exception>
    public static CkmHkdfParams WithSalt(HkdfOperation operation, CKM prfHashMechanism, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info = default)
    {
        if (salt.IsEmpty)
            throw new ArgumentException("Salt must not be empty; use WithoutSalt for RFC 5869's default salt.", nameof(salt));
        return new(operation, prfHashMechanism, HkdfSaltType.Data, salt, null, info);
    }

    /// <summary>
    /// HKDF parameters salted with the value of an on-token secret key (<c>CKF_HKDF_SALT_KEY</c>), so
    /// the salt never leaves the token.
    /// </summary>
    /// <remarks>
    /// <paramref name="saltKey"/> must come from the workspace that performs the derive; it is resolved
    /// to its object handle when the operation runs, and a disposed key or one from another workspace
    /// is refused there.
    /// </remarks>
    /// <param name="operation">Which HKDF step(s) to perform.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="saltKey">The key whose value is the salt.</param>
    /// <param name="info">Application-specific context bytes.</param>
    /// <returns>The parameters.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="saltKey"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="saltKey"/> has no secret-key object.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="operation"/> is not a defined <see cref="HkdfOperation"/> member.</exception>
    public static CkmHkdfParams WithSaltKey(HkdfOperation operation, CKM prfHashMechanism, Pkcs11Key saltKey, ReadOnlySpan<byte> info = default)
    {
        ArgumentNullException.ThrowIfNull(saltKey);
        saltKey.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(saltKey));
        return new(operation, prfHashMechanism, HkdfSaltType.Key, default, saltKey, info);
    }

    /// <summary>The PRF hash mechanism (typically a <c>CKM_*_HMAC</c> variant, or the bare hash), for policy evaluation.</summary>
    internal CKM PrfHashMechanism => _prfHashMechanism;

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_HKDF_PARAMS
        {
            Extract = CkBbool.From(_extract),
            Expand = CkBbool.From(_expand),
            PrfHashMechanism = CkULong.From((ulong)_prfHashMechanism, "prfHashMechanism"),
            SaltType = CkULong.From((ulong)_saltType, "saltType"),
            Salt = scope.Write(_saltBytes),
            SaltLen = (NativeCULong)_saltBytes.Length,
            SaltKey = _saltKey is null ? default : scope.KeyHandle(_saltKey, KeyHandlePart.Private, "saltKey"),
            Info = scope.Write(_infoBytes),
            InfoLen = (NativeCULong)_infoBytes.Length,
        });
    }
}
