using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_HKDF_PARAMS"/>. Used with CKM_HKDF_DERIVE / CKM_HKDF_DATA / CKM_HKDF_KEY_GEN (PKCS#11 v3.0).
/// </summary>
public sealed class CkmHkdfParams : MechanismParameters
{
    private readonly byte[] _saltBytes;
    private readonly byte[] _infoBytes;
    private readonly bool _extract;
    private readonly bool _expand;
    private readonly CKM _prfHashMechanism;
    private readonly ulong _saltType;
    private readonly ulong _saltKey;

    /// <summary>
    /// Initializes the HKDF parameters.
    /// </summary>
    /// <param name="operation">Which HKDF step(s) to perform.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="saltType">Salt source.</param>
    /// <param name="salt">Salt bytes when <paramref name="saltType"/> is <see cref="HkdfSaltType.Data"/>; ignored otherwise.</param>
    /// <param name="saltKey">Salt key handle when <paramref name="saltType"/> is <see cref="HkdfSaltType.Key"/>; ignored otherwise.</param>
    /// <param name="info">Application-specific context bytes.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="operation"/> is not a defined <see cref="HkdfOperation"/> member.</exception>
    public CkmHkdfParams(HkdfOperation operation, CKM prfHashMechanism, HkdfSaltType saltType,
        ReadOnlySpan<byte> salt = default, ulong saltKey = 0, ReadOnlySpan<byte> info = default)
    {
        _saltBytes = salt.IsEmpty ? [] : salt.ToArray();
        _infoBytes = info.IsEmpty ? [] : info.ToArray();
        (_extract, _expand) = operation switch
        {
            HkdfOperation.ExtractOnly => (true, false),
            HkdfOperation.ExpandOnly => (false, true),
            HkdfOperation.ExtractAndExpand => (true, true),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Not a defined HkdfOperation member."),
        };
        _prfHashMechanism = prfHashMechanism;
        _saltType = (ulong)saltType;
        _saltKey = saltKey;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_HKDF_PARAMS
        {
            Extract = _extract,
            Expand = _expand,
            PrfHashMechanism = (NativeCULong)(ulong)_prfHashMechanism,
            SaltType = (NativeCULong)_saltType,
            Salt = scope.Write(_saltBytes),
            SaltLen = (NativeCULong)_saltBytes.Length,
            SaltKey = (NativeCULong)_saltKey,
            Info = scope.Write(_infoBytes),
            InfoLen = (NativeCULong)_infoBytes.Length,
        };
    }
}
