using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_PSS_PARAMS"/>. A managed descriptor of three
/// integers, rebuilt into each call's own scope like every other parameter type.
/// </summary>
public sealed class CkmRsaPkcsPssParams : MechanismParameters
{
    private readonly CKM _hashAlg;
    private readonly CKG _mgf;
    private readonly int _saltLength;

    /// <summary>
    /// Initializes RSA-PSS parameters.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="saltLength">Salt length in bytes. RFC 8017 recommends matching the hash output length (32 for SHA-256).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="saltLength"/> is negative.</exception>
    public CkmRsaPkcsPssParams(CKM hashAlg, CKG mgf, int saltLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(saltLength);

        _hashAlg = hashAlg;
        _mgf = mgf;
        _saltLength = saltLength;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_RSA_PKCS_PSS_PARAMS
        {
            HashAlg = _hashAlg.ToCULong(),
            Mgf = _mgf.ToCULong(),
            Len = (NativeCULong)_saltLength,
        };
    }

    /// <summary>Hash algorithm used in the PSS encoding.</summary>
    public CKM HashAlg => _hashAlg;

    /// <summary>Mask generation function.</summary>
    public CKG Mgf => _mgf;

    /// <summary>Salt length in bytes.</summary>
    public int SaltLength => _saltLength;
}
