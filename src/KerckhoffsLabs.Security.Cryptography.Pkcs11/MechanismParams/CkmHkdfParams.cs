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
    /// <param name="extract">Perform the HKDF-Extract step.</param>
    /// <param name="expand">Perform the HKDF-Expand step.</param>
    /// <param name="prfHashMechanism">PRF mechanism (typically a CKM_*_HMAC variant).</param>
    /// <param name="saltType">Salt type: 1 = SALT_NULL, 2 = SALT_DATA, 4 = SALT_KEY.</param>
    /// <param name="salt">Salt bytes when saltType = SALT_DATA; pass <c>default</c> otherwise.</param>
    /// <param name="saltKey">Salt key handle when saltType = SALT_KEY; pass 0 otherwise.</param>
    /// <param name="info">Application-specific context bytes.</param>
    public CkmHkdfParams(bool extract, bool expand, CKM prfHashMechanism, ulong saltType, ReadOnlySpan<byte> salt, ulong saltKey, ReadOnlySpan<byte> info)
    {
        _saltBytes = salt.IsEmpty ? [] : salt.ToArray();
        _infoBytes = info.IsEmpty ? [] : info.ToArray();
        _extract = extract;
        _expand = expand;
        _prfHashMechanism = prfHashMechanism;
        _saltType = saltType;
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
